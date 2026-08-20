using System.Text.Json;

namespace MesaShield.Core;

/// <summary>A point-in-time status snapshot for one machine, shared with the fleet dashboard.</summary>
public sealed record MachineStatus
{
    public required string MachineName { get; init; }
    public required string Version { get; init; }
    public DateTimeOffset ReportedUtc { get; init; } = DateTimeOffset.UtcNow;

    public bool RealTimeProtection { get; init; }
    public bool BehaviorGuard { get; init; }
    public bool ProcessMonitoring { get; init; }
    public bool AdaptiveLearning { get; init; }

    public int SignatureCount { get; init; }
    public DateTimeOffset? SignaturesUpdatedUtc { get; init; }

    public long ThreatsHandled { get; init; }
    public int InQuarantine { get; init; }
    public long RecentAlerts24h { get; init; }

    public bool LearnerLearning { get; init; }
    public long LearnerObservations { get; init; }

    public DateTimeOffset? LastScanUtc { get; init; }
    public string? LastScanSummary { get; init; }

    /// <summary>Overall health rollup for the dashboard's at-a-glance colour.</summary>
    public string Health
    {
        get
        {
            if (!RealTimeProtection) return "at-risk";
            if (RecentAlerts24h > 0) return "attention";
            if (SignatureCount == 0) return "attention";
            return "protected";
        }
    }

    /// <summary>True if we haven't heard from this machine recently (stale heartbeat).</summary>
    public bool IsStale(TimeSpan maxAge) => DateTimeOffset.UtcNow - ReportedUtc > maxAge;
}

/// <summary>
/// Writes this machine's status to a local file and, when configured, to a shared folder
/// (e.g. \\SERVER\MesaShield\status) so a Fleet dashboard on any machine can read every
/// machine's status. Everything stays on the LAN — no cloud, no external service.
/// </summary>
public sealed class FleetReporter
{
    private readonly string _localPath;
    private readonly Func<MachineStatus> _snapshot;
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    public string? SharedFolder { get; set; }

    public FleetReporter(string localPath, Func<MachineStatus> snapshot)
    {
        _localPath = localPath;
        _snapshot = snapshot;
    }

    /// <summary>Safe filename for a machine's status within the shared folder.</summary>
    public static string StatusFileName(string machineName)
    {
        var safe = new string(machineName.Select(c => char.IsLetterOrDigit(c) || c is '-' or '_' ? c : '_').ToArray());
        return safe + ".json";
    }

    public void Report()
    {
        var status = _snapshot();
        var json = JsonSerializer.Serialize(status, JsonOptions);

        WriteAtomic(_localPath, json);

        if (!string.IsNullOrWhiteSpace(SharedFolder))
        {
            try
            {
                Directory.CreateDirectory(SharedFolder);
                WriteAtomic(Path.Combine(SharedFolder, StatusFileName(status.MachineName)), json);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // Shared folder unreachable (server offline, no permission) — local report still succeeds.
            }
        }
    }

    private static void WriteAtomic(string path, string content)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var tmp = path + ".tmp";
        File.WriteAllText(tmp, content);
        File.Move(tmp, path, overwrite: true);
    }
}

/// <summary>Reads every machine's status file from the shared folder for the Fleet dashboard.</summary>
public static class FleetReader
{
    public static List<MachineStatus> ReadAll(string sharedFolder)
    {
        var results = new List<MachineStatus>();
        if (!Directory.Exists(sharedFolder)) return results;

        foreach (var file in Directory.EnumerateFiles(sharedFolder, "*.json"))
        {
            try
            {
                var status = JsonSerializer.Deserialize<MachineStatus>(File.ReadAllText(file));
                if (status is not null) results.Add(status);
            }
            catch (Exception ex) when (ex is JsonException or IOException)
            {
                // Skip a partial/locked file; it'll be read next refresh.
            }
        }
        return results.OrderBy(s => s.MachineName, StringComparer.OrdinalIgnoreCase).ToList();
    }
}
