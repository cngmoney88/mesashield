using System.Collections.Concurrent;
using MesaShield.Core;

namespace MesaShield.Windows;

/// <summary>
/// Real-time protection: watches high-risk folders (Downloads, Desktop, Temp, and any
/// removable drive that appears) and scans files the moment they are created or
/// modified. Malicious findings are quarantined automatically; suspicious ones are
/// surfaced through <see cref="ThreatHandled"/> for the UI to show.
/// </summary>
public sealed class RealTimeProtector : IDisposable
{
    private readonly ScanEngine _engine;
    private readonly QuarantineManager _quarantine;
    private readonly ShieldEventLog _log;
    private readonly ScanOptions _options;
    private readonly List<FileSystemWatcher> _watchers = new();
    private readonly ConcurrentDictionary<string, DateTimeOffset> _pending = new(StringComparer.OrdinalIgnoreCase);
    private CancellationTokenSource _cts = new();
    private Task? _pump;

    /// <summary>Raised after a detection has been acted on (quarantined or flagged).</summary>
    public event Action<ThreatFinding, bool /*quarantined*/>? ThreatHandled;

    /// <summary>Raised when a watcher fails (e.g. drive removed); informational.</summary>
    public event Action<string>? WatcherError;

    public bool IsRunning { get; private set; }
    public IReadOnlyList<string> WatchedPaths => _watchers.Select(w => w.Path).ToList();

    public RealTimeProtector(ScanEngine engine, QuarantineManager quarantine, ShieldEventLog log, ScanOptions? options = null)
    {
        _engine = engine;
        _quarantine = quarantine;
        _log = log;
        _options = options ?? new ScanOptions();
    }

    /// <summary>Default high-risk folders for the current user.</summary>
    public static List<string> DefaultWatchPaths()
    {
        var paths = new List<string>();
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        void AddIfExists(string p) { if (Directory.Exists(p)) paths.Add(p); }

        AddIfExists(Path.Combine(userProfile, "Downloads"));
        AddIfExists(Environment.GetFolderPath(Environment.SpecialFolder.Desktop));
        AddIfExists(Path.GetTempPath());
        return paths;
    }

    public void Start(IEnumerable<string>? watchPaths = null)
    {
        if (IsRunning) return;
        if (_cts.IsCancellationRequested) _cts = new CancellationTokenSource();
        foreach (var path in watchPaths ?? DefaultWatchPaths())
            AddWatch(path);

        _pump = Task.Run(() => PumpAsync(_cts.Token));
        IsRunning = true;
        _ = _log.LogAsync("realtime", $"Real-time protection started. Watching: {string.Join("; ", WatchedPaths)}");
    }

    /// <summary>Stop watching. Safe to call Start() again afterwards.</summary>
    public void Stop()
    {
        if (!IsRunning) return;
        _cts.Cancel();
        foreach (var watcher in _watchers) watcher.Dispose();
        _watchers.Clear();
        _pending.Clear();
        IsRunning = false;
        _ = _log.LogAsync("realtime", "Real-time protection stopped.");
    }

    /// <summary>Add a folder or drive root to the watch set at runtime (used for USB insertion).</summary>
    public void AddWatch(string path)
    {
        if (!Directory.Exists(path)) return;
        if (_watchers.Any(w => string.Equals(w.Path, path, StringComparison.OrdinalIgnoreCase))) return;

        var watcher = new FileSystemWatcher(path)
        {
            IncludeSubdirectories = true,
            NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size,
            InternalBufferSize = 64 * 1024,
        };
        watcher.Created += (_, e) => Enqueue(e.FullPath);
        watcher.Changed += (_, e) => Enqueue(e.FullPath);
        watcher.Renamed += (_, e) => Enqueue(e.FullPath);
        watcher.Error += (_, e) => WatcherError?.Invoke($"{path}: {e.GetException().Message}");
        watcher.EnableRaisingEvents = true;
        _watchers.Add(watcher);
    }

    public void RemoveWatch(string path)
    {
        foreach (var watcher in _watchers.Where(w =>
                     string.Equals(w.Path, path, StringComparison.OrdinalIgnoreCase)).ToList())
        {
            watcher.EnableRaisingEvents = false;
            watcher.Dispose();
            _watchers.Remove(watcher);
        }
    }

    private void Enqueue(string path)
    {
        // Debounce: a file being downloaded fires many Changed events. We stamp the
        // last event time and only scan once the file has been quiet for a moment.
        _pending[path] = DateTimeOffset.UtcNow;
    }

    private async Task PumpAsync(CancellationToken ct)
    {
        var quietPeriod = TimeSpan.FromSeconds(1.5);
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(500, ct).ConfigureAwait(false);
                var now = DateTimeOffset.UtcNow;

                foreach (var (path, lastEvent) in _pending)
                {
                    if (now - lastEvent < quietPeriod) continue;
                    if (!_pending.TryRemove(path, out _)) continue;
                    if (!File.Exists(path)) continue;
                    if (path.Contains("\\MesaShield\\Quarantine\\", StringComparison.OrdinalIgnoreCase)) continue;

                    await ScanAndActAsync(path, ct).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                await _log.LogAsync("error", $"Real-time pump error: {ex.Message}").ConfigureAwait(false);
            }
        }
    }

    private async Task ScanAndActAsync(string path, CancellationToken ct)
    {
        var result = await _engine.ScanFileAsync(path, _options, ct).ConfigureAwait(false);
        foreach (var finding in result.Findings)
        {
            if (finding.Severity == ThreatSeverity.Malicious)
            {
                var entry = await _quarantine.QuarantineAsync(finding, ct).ConfigureAwait(false);
                await _log.LogAsync("quarantine",
                    $"Real-time protection quarantined {finding.ThreatName}",
                    finding.FilePath, finding.ThreatName).ConfigureAwait(false);
                ThreatHandled?.Invoke(finding, entry is not null);
            }
            else
            {
                await _log.LogAsync("detection",
                    $"Real-time protection flagged a suspicious file: {finding.Detail}",
                    finding.FilePath, finding.ThreatName).ConfigureAwait(false);
                ThreatHandled?.Invoke(finding, false);
            }
        }
    }

    public void Dispose()
    {
        Stop();
        _cts.Dispose();
    }
}
