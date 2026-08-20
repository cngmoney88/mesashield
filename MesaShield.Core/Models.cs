namespace MesaShield.Core;

/// <summary>How a threat was identified.</summary>
public enum DetectionMethod
{
    /// <summary>Exact SHA-256 match against the known-malware signature database.</summary>
    SignatureHash,
    /// <summary>Matched a byte/string pattern rule (MesaShield rule or YARA).</summary>
    Pattern,
    /// <summary>Flagged by heuristic analysis (entropy, PE anomalies, double extensions, etc.).</summary>
    Heuristic,
    /// <summary>Flagged by the Windows Antimalware Scan Interface (AMSI) — script/runtime content.</summary>
    Amsi,
    /// <summary>Flagged by a cloud reputation service (e.g. VirusTotal).</summary>
    CloudReputation,
    /// <summary>Flagged by behavioral analysis (ransomware activity, etc.).</summary>
    Behavior,
    /// <summary>Flagged by the on-device anomaly learner (unusual for this machine).</summary>
    Anomaly,
    /// <summary>Flagged by the offline machine-learning malware classifier.</summary>
    MachineLearning,
}

/// <summary>
/// Optional hook for scanning script/content buffers through an external engine
/// (implemented over Windows AMSI). Kept as an interface so the cross-platform Core
/// stays free of Windows dependencies.
/// </summary>
public interface IScriptScanner
{
    bool IsAvailable { get; }
    Task<bool> ScanFileMaliciousAsync(string path, CancellationToken ct = default);
}

/// <summary>Severity of a finding.</summary>
public enum ThreatSeverity
{
    /// <summary>Suspicious but not confirmed — surfaced to the user, not auto-quarantined by default.</summary>
    Suspicious,
    /// <summary>Confirmed or high-confidence malware — quarantined.</summary>
    Malicious,
}

/// <summary>A single finding produced by the scan engine for one file.</summary>
public sealed record ThreatFinding
{
    public required string FilePath { get; init; }
    public required string ThreatName { get; init; }
    public required DetectionMethod Method { get; init; }
    public required ThreatSeverity Severity { get; init; }
    public string? Sha256 { get; init; }
    public string? Detail { get; init; }
    public DateTimeOffset DetectedAt { get; init; } = DateTimeOffset.UtcNow;
}

/// <summary>Result of scanning a single file.</summary>
public sealed record FileScanResult
{
    public required string FilePath { get; init; }
    public bool WasScanned { get; init; } = true;
    public string? SkipReason { get; init; }
    public IReadOnlyList<ThreatFinding> Findings { get; init; } = Array.Empty<ThreatFinding>();
    public bool IsClean => WasScanned && Findings.Count == 0;
}

/// <summary>Summary of a whole scan job.</summary>
public sealed class ScanSummary
{
    public DateTimeOffset StartedAt { get; init; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? FinishedAt { get; set; }
    public long FilesScanned { get; set; }
    public long FilesSkipped { get; set; }
    public long BytesScanned { get; set; }
    public List<ThreatFinding> Findings { get; } = new();
    public bool WasCancelled { get; set; }
}

/// <summary>Progress callback payload during a scan.</summary>
public sealed record ScanProgress(string CurrentFile, long FilesScanned, long ThreatsFound);

/// <summary>Options controlling a scan job.</summary>
public sealed class ScanOptions
{
    /// <summary>Files larger than this are hash-checked but not pattern/heuristic scanned. Default 256 MB.</summary>
    public long MaxDeepScanBytes { get; set; } = 256L * 1024 * 1024;

    /// <summary>Files larger than this are skipped entirely. Default 4 GB.</summary>
    public long MaxFileBytes { get; set; } = 4L * 1024 * 1024 * 1024;

    /// <summary>Directories (full path prefixes) to exclude.</summary>
    public List<string> ExcludedPaths { get; } = new();

    /// <summary>Extensions to exclude (e.g. ".iso"). Lower-case with dot.</summary>
    public HashSet<string> ExcludedExtensions { get; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Degree of parallelism. Default: processor count, capped at 8.</summary>
    public int Parallelism { get; set; } = Math.Min(Environment.ProcessorCount, 8);

    /// <summary>Scan inside archives (zip). Default true, one level deep.</summary>
    public bool ScanArchives { get; set; } = true;
}
