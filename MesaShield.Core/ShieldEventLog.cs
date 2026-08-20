using System.Text.Json;

namespace MesaShield.Core;

/// <summary>Append-only JSONL event log: detections, scans, quarantines, updates.</summary>
public sealed class ShieldEventLog
{
    private readonly string _logDirectory;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public ShieldEventLog(string logDirectory)
    {
        _logDirectory = logDirectory;
        Directory.CreateDirectory(logDirectory);
    }

    public sealed record ShieldEvent(
        DateTimeOffset Timestamp, string Kind, string Message, string? FilePath = null, string? ThreatName = null);

    public Task LogAsync(string kind, string message, string? filePath = null, string? threatName = null) =>
        AppendAsync(new ShieldEvent(DateTimeOffset.UtcNow, kind, message, filePath, threatName));

    private async Task AppendAsync(ShieldEvent evt)
    {
        var path = Path.Combine(_logDirectory, $"events-{evt.Timestamp:yyyy-MM}.jsonl");
        var line = JsonSerializer.Serialize(evt) + Environment.NewLine;
        await _gate.WaitAsync().ConfigureAwait(false);
        try { await File.AppendAllTextAsync(path, line).ConfigureAwait(false); }
        finally { _gate.Release(); }
    }

    /// <summary>Read the most recent events, newest first.</summary>
    public async Task<List<ShieldEvent>> ReadRecentAsync(int maxCount = 500, CancellationToken ct = default)
    {
        var events = new List<ShieldEvent>();
        var files = Directory.EnumerateFiles(_logDirectory, "events-*.jsonl")
            .OrderByDescending(f => f);

        foreach (var file in files)
        {
            foreach (var line in await File.ReadAllLinesAsync(file, ct).ConfigureAwait(false))
            {
                try
                {
                    var evt = JsonSerializer.Deserialize<ShieldEvent>(line);
                    if (evt is not null) events.Add(evt);
                }
                catch (JsonException) { /* skip corrupt line */ }
            }
            if (events.Count >= maxCount) break;
        }

        return events.OrderByDescending(e => e.Timestamp).Take(maxCount).ToList();
    }
}
