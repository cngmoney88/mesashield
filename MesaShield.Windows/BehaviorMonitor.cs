using System.Diagnostics;
using MesaShield.Core;

namespace MesaShield.Windows;

/// <summary>
/// Windows wiring for the <see cref="BehaviorEngine"/>. Deploys canary files, watches
/// the user's document folders for changes, estimates the entropy of freshly written
/// files (the encryption fingerprint), and — when the engine raises a malicious alert —
/// tries to suspend/kill the offending process and surfaces the alert to the UI.
/// </summary>
public sealed class BehaviorMonitor : IDisposable
{
    private readonly BehaviorEngine _engine;
    private readonly ShieldEventLog _log;
    private readonly List<FileSystemWatcher> _watchers = new();
    private readonly CancellationTokenSource _cts = new();

    public event Action<BehaviorAlert>? AlertRaised;
    public bool IsRunning { get; private set; }

    public BehaviorMonitor(BehaviorEngine engine, ShieldEventLog log)
    {
        _engine = engine;
        _log = log;
        _engine.AlertRaised += OnAlert;
    }

    public static List<string> DefaultProtectedFolders()
    {
        var folders = new List<string>();
        void Add(Environment.SpecialFolder f)
        {
            var p = Environment.GetFolderPath(f);
            if (!string.IsNullOrEmpty(p) && Directory.Exists(p)) folders.Add(p);
        }
        Add(Environment.SpecialFolder.MyDocuments);
        Add(Environment.SpecialFolder.MyPictures);
        Add(Environment.SpecialFolder.Desktop);
        return folders;
    }

    public void Start(IEnumerable<string>? protectedFolders = null)
    {
        if (IsRunning) return;
        var folders = (protectedFolders ?? DefaultProtectedFolders()).ToList();

        var canaries = CanaryDeployer.Deploy(folders, _engine);
        foreach (var folder in folders)
        {
            try
            {
                var watcher = new FileSystemWatcher(folder)
                {
                    IncludeSubdirectories = true,
                    NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName | NotifyFilters.Size,
                    InternalBufferSize = 64 * 1024,
                };
                watcher.Changed += OnChanged;
                watcher.Created += OnChanged;
                watcher.Renamed += OnRenamed;
                watcher.EnableRaisingEvents = true;
                _watchers.Add(watcher);
            }
            catch (Exception ex) when (ex is IOException or ArgumentException)
            {
                // Skip folders we can't watch.
            }
        }

        IsRunning = true;
        _ = _log.LogAsync("behavior",
            $"Ransomware behavior guard started. Protecting {folders.Count} folder(s), {canaries.Count} canary file(s) deployed.");
    }

    private void OnRenamed(object sender, RenamedEventArgs e) => Evaluate(e.FullPath);
    private void OnChanged(object sender, FileSystemEventArgs e) => Evaluate(e.FullPath);

    private void Evaluate(string path)
    {
        if (Directory.Exists(path)) return; // directory event, not a file

        // Don't touch online-only cloud placeholders — reading them would force a download,
        // and a placeholder isn't being actively encrypted.
        try
        {
            if (ScanEngine.IsOnlineOnly(File.GetAttributes(path))) return;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return; }

        double? entropy = EstimateEntropy(path);
        _engine.OnFileChanged(path, DateTimeOffset.UtcNow, processId: null, newContentEntropy: entropy);
    }

    /// <summary>Sample the head of a file to estimate content entropy (0-8). Best-effort.</summary>
    private static double? EstimateEntropy(string path)
    {
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete, 4096, FileOptions.SequentialScan);
            var buffer = new byte[Math.Min(4096, (int)Math.Min(stream.Length, 4096))];
            var read = stream.Read(buffer, 0, buffer.Length);
            return read > 256 ? HeuristicAnalyzer.ShannonEntropy(buffer.AsSpan(0, read)) : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    private void OnAlert(BehaviorAlert alert)
    {
        // Try to stop the offending process if we know it.
        if (alert.Severity == ThreatSeverity.Malicious && alert.SuspectProcessId is { } pid)
        {
            try
            {
                using var process = Process.GetProcessById(pid);
                process.Kill(entireProcessTree: true);
                _ = _log.LogAsync("behavior", $"Terminated suspected ransomware process (PID {pid}): {alert.Kind}");
            }
            catch (Exception) { /* already gone or protected */ }
        }

        _ = _log.LogAsync(
            alert.Severity == ThreatSeverity.Malicious ? "blocked" : "detection",
            alert.Message, alert.AffectedFiles.FirstOrDefault(), alert.Kind);
        AlertRaised?.Invoke(alert);
    }

    public void Stop()
    {
        foreach (var watcher in _watchers) watcher.Dispose();
        _watchers.Clear();
        IsRunning = false;
    }

    public void Dispose()
    {
        _engine.AlertRaised -= OnAlert;
        Stop();
        _cts.Cancel();
        _cts.Dispose();
    }
}
