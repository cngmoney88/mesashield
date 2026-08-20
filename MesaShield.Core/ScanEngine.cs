using System.IO.Compression;
using System.Threading.Channels;

namespace MesaShield.Core;

/// <summary>
/// Orchestrates a scan: walks directories, runs each file through the three detection
/// layers (signature hash, pattern rules, heuristics), optionally looks one level into
/// zip archives, and streams progress back to the caller.
/// </summary>
public sealed class ScanEngine
{
    private readonly SignatureDatabase _signatures;
    private readonly PatternScanner _patterns;
    private readonly HeuristicAnalyzer _heuristics;

    /// <summary>Optional AMSI-backed script scanner (set on Windows).</summary>
    public IScriptScanner? ScriptScanner { get; set; }

    /// <summary>Optional cloud reputation client. Consulted only to escalate already-suspicious files.</summary>
    public ReputationClient? Reputation { get; set; }

    /// <summary>Optional offline ML malware classifier (scores PE files locally).</summary>
    public Ml.MalwareClassifier? Classifier { get; set; }

    private static readonly HashSet<string> ScriptExtensions = new(StringComparer.OrdinalIgnoreCase)
    { ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".bat", ".cmd", ".hta" };

    public ScanEngine(SignatureDatabase signatures, PatternScanner patterns, HeuristicAnalyzer heuristics)
    {
        _signatures = signatures;
        _patterns = patterns;
        _heuristics = heuristics;
    }

    /// <summary>Scan a single file.</summary>
    public async Task<FileScanResult> ScanFileAsync(
        string path, ScanOptions options, CancellationToken ct = default)
    {
        FileInfo info;
        try
        {
            info = new FileInfo(path);
            if (!info.Exists)
                return Skipped(path, "File no longer exists");
            if (IsOnlineOnly(info.Attributes))
                return Skipped(path, "Online-only cloud file (not downloaded — skipped to avoid forcing a download)");
            if (info.Length == 0)
                return new FileScanResult { FilePath = path };
            if (info.Length > options.MaxFileBytes)
                return Skipped(path, $"File exceeds size limit ({info.Length:N0} bytes)");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return Skipped(path, ex.Message);
        }

        var findings = new List<ThreatFinding>();

        try
        {
            // Layer 1: signature hash.
            var sha256 = await FileHasher.Sha256Async(path, ct).ConfigureAwait(false);
            if (_signatures.Contains(sha256))
            {
                findings.Add(new ThreatFinding
                {
                    FilePath = path,
                    ThreatName = _signatures.ThreatNameFor(sha256),
                    Method = DetectionMethod.SignatureHash,
                    Severity = ThreatSeverity.Malicious,
                    Sha256 = sha256,
                    Detail = "Exact match against the known-malware signature database.",
                });
                // A confirmed signature hit is conclusive; no need for deeper layers.
                return new FileScanResult { FilePath = path, Findings = findings };
            }

            if (info.Length <= options.MaxDeepScanBytes)
            {
                // Layer 2: pattern rules over the full stream.
                var extension = Path.GetExtension(path);
                await using (var stream = OpenRead(path))
                {
                    foreach (var rule in await _patterns.ScanStreamAsync(stream, extension, ct).ConfigureAwait(false))
                    {
                        findings.Add(new ThreatFinding
                        {
                            FilePath = path,
                            ThreatName = rule.Name,
                            Method = DetectionMethod.Pattern,
                            Severity = rule.Severity,
                            Sha256 = sha256,
                            Detail = rule.Description,
                        });
                    }
                }

                // Layer 3: heuristics over the head of the file.
                var headLength = (int)Math.Min(info.Length, 8 * 1024 * 1024);
                var head = new byte[headLength];
                await using (var stream = OpenRead(path))
                {
                    await stream.ReadExactlyAsync(head, ct).ConfigureAwait(false);
                }
                foreach (var finding in _heuristics.Analyze(path, head, info.Length))
                    findings.Add(finding with { Sha256 = sha256 });

                // Layer: offline ML classifier over PE files. Adds an independent opinion learned
                // from a large malware/clean corpus, catching novel files signatures don't cover.
                if (Classifier is { IsUsable: true } && HeuristicAnalyzer.IsPeFile(head))
                {
                    var verdict = Classifier.Classify(head, info.Length);
                    if (verdict is { } v)
                    {
                        findings.Add(new ThreatFinding
                        {
                            FilePath = path,
                            ThreatName = $"ML.Suspicious ({v.Probability:P0} confidence)",
                            Method = DetectionMethod.MachineLearning,
                            Severity = v.Severity,
                            Sha256 = sha256,
                            Detail = $"Offline machine-learning classifier scored this file {v.Probability:P0} likely malicious (model {Classifier.Version}).",
                        });
                    }
                }

                // Layer 4: AMSI script scanning (Windows). Catches obfuscated/runtime-decoded scripts.
                if (ScriptScanner is { IsAvailable: true } && ScriptExtensions.Contains(extension))
                {
                    if (await ScriptScanner.ScanFileMaliciousAsync(path, ct).ConfigureAwait(false))
                    {
                        findings.Add(new ThreatFinding
                        {
                            FilePath = path,
                            ThreatName = "AMSI.ScriptMalware",
                            Method = DetectionMethod.Amsi,
                            Severity = ThreatSeverity.Malicious,
                            Sha256 = sha256,
                            Detail = "Flagged by the Windows Antimalware Scan Interface (script/runtime content).",
                        });
                    }
                }

                // Archives: hash-check entries one level deep.
                if (options.ScanArchives && extension.Equals(".zip", StringComparison.OrdinalIgnoreCase))
                    await ScanZipEntriesAsync(path, findings, ct).ConfigureAwait(false);

                // Layer 5: cloud reputation — only to escalate a file that's already suspicious
                // (keeps us well within free-tier API limits during full scans).
                if (Reputation is { IsEnabled: true } &&
                    findings.Count > 0 && findings.All(f => f.Severity == ThreatSeverity.Suspicious))
                {
                    var rep = await Reputation.LookupAsync(sha256, ct).ConfigureAwait(false);
                    if (rep.Verdict == ReputationVerdict.Malicious)
                    {
                        findings.Add(new ThreatFinding
                        {
                            FilePath = path,
                            ThreatName = rep.Label ?? "Cloud.KnownMalware",
                            Method = DetectionMethod.CloudReputation,
                            Severity = ThreatSeverity.Malicious,
                            Sha256 = sha256,
                            Detail = $"Cloud reputation: flagged by {rep.Positives} of {rep.Total} engines.",
                        });
                    }
                }
            }
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return Skipped(path, ex.Message);
        }

        return new FileScanResult { FilePath = path, Findings = findings };
    }

    /// <summary>Scan a set of files/directories in parallel with live progress.</summary>
    public async Task<ScanSummary> ScanAsync(
        IEnumerable<string> targets,
        ScanOptions options,
        IProgress<ScanProgress>? progress = null,
        Func<FileScanResult, Task>? onResult = null,
        CancellationToken ct = default)
    {
        var summary = new ScanSummary();
        var channel = Channel.CreateBounded<string>(new BoundedChannelOptions(4096)
        { SingleWriter = true, FullMode = BoundedChannelFullMode.Wait });

        var producer = Task.Run(async () =>
        {
            try
            {
                foreach (var target in targets)
                foreach (var file in EnumerateFiles(target, options))
                {
                    ct.ThrowIfCancellationRequested();
                    await channel.Writer.WriteAsync(file, ct).ConfigureAwait(false);
                }
            }
            finally { channel.Writer.Complete(); }
        }, ct);

        var gate = new SemaphoreSlim(1, 1);
        var workers = Enumerable.Range(0, Math.Max(1, options.Parallelism)).Select(_ => Task.Run(async () =>
        {
            await foreach (var file in channel.Reader.ReadAllAsync(ct).ConfigureAwait(false))
            {
                var result = await ScanFileAsync(file, options, ct).ConfigureAwait(false);
                long length = 0;
                try { length = result.WasScanned ? new FileInfo(file).Length : 0; } catch { /* best effort */ }

                await gate.WaitAsync(ct).ConfigureAwait(false);
                try
                {
                    if (result.WasScanned) { summary.FilesScanned++; summary.BytesScanned += length; }
                    else summary.FilesSkipped++;
                    summary.Findings.AddRange(result.Findings);
                    progress?.Report(new ScanProgress(file, summary.FilesScanned, summary.Findings.Count));
                }
                finally { gate.Release(); }

                if (onResult is not null)
                    await onResult(result).ConfigureAwait(false);
            }
        }, ct)).ToArray();

        try
        {
            await Task.WhenAll(workers.Append(producer)).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            summary.WasCancelled = true;
        }

        summary.FinishedAt = DateTimeOffset.UtcNow;
        return summary;
    }

    private async Task ScanZipEntriesAsync(string zipPath, List<ThreatFinding> findings, CancellationToken ct)
    {
        try
        {
            using var archive = ZipFile.OpenRead(zipPath);
            foreach (var entry in archive.Entries)
            {
                ct.ThrowIfCancellationRequested();
                if (entry.Length is 0 or > 128 * 1024 * 1024) continue;

                await using var entryStream = entry.Open();
                using var buffer = new MemoryStream((int)entry.Length);
                await entryStream.CopyToAsync(buffer, ct).ConfigureAwait(false);
                var sha256 = FileHasher.Sha256(buffer.GetBuffer().AsSpan(0, (int)buffer.Length));

                if (_signatures.Contains(sha256))
                {
                    findings.Add(new ThreatFinding
                    {
                        FilePath = zipPath,
                        ThreatName = _signatures.ThreatNameFor(sha256),
                        Method = DetectionMethod.SignatureHash,
                        Severity = ThreatSeverity.Malicious,
                        Sha256 = sha256,
                        Detail = $"Inside archive: {entry.FullName}",
                    });
                }
                else
                {
                    buffer.Position = 0;
                    var rules = await _patterns.ScanStreamAsync(
                        buffer, Path.GetExtension(entry.Name), ct).ConfigureAwait(false);
                    foreach (var rule in rules)
                    {
                        findings.Add(new ThreatFinding
                        {
                            FilePath = zipPath,
                            ThreatName = rule.Name,
                            Method = DetectionMethod.Pattern,
                            Severity = rule.Severity,
                            Sha256 = sha256,
                            Detail = $"Inside archive: {entry.FullName}. {rule.Description}",
                        });
                    }
                }
            }
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException)
        {
            // Corrupt or locked archive — not a threat by itself.
        }
    }

    private static IEnumerable<string> EnumerateFiles(string target, ScanOptions options)
    {
        if (File.Exists(target))
        {
            yield return target;
            yield break;
        }
        if (!Directory.Exists(target)) yield break;

        var enumeration = new EnumerationOptions
        {
            RecurseSubdirectories = true,
            IgnoreInaccessible = true,
            // Skip reparse points, devices, and online-only cloud placeholders (Offline).
            AttributesToSkip = FileAttributes.ReparsePoint | FileAttributes.Device | FileAttributes.Offline,
        };

        foreach (var file in Directory.EnumerateFiles(target, "*", enumeration))
        {
            if (options.ExcludedExtensions.Contains(Path.GetExtension(file))) continue;
            if (options.ExcludedPaths.Any(p => file.StartsWith(p, StringComparison.OrdinalIgnoreCase))) continue;
            yield return file;
        }
    }

    // OneDrive / cloud "files on demand" mark online-only placeholders with these attributes.
    // Reading them would force a download, so we skip them — a placeholder can't be an active
    // threat, and it'll be scanned naturally if the user ever actually opens it.
    private const FileAttributes Offline = FileAttributes.Offline;                 // 0x1000
    private const FileAttributes RecallOnDataAccess = (FileAttributes)0x400000;    // not in the enum

    public static bool IsOnlineOnly(FileAttributes attributes) =>
        (attributes & (Offline | RecallOnDataAccess)) != 0;

    private static FileStream OpenRead(string path) => new(
        path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete,
        bufferSize: 1 << 20, options: FileOptions.Asynchronous | FileOptions.SequentialScan);

    private static FileScanResult Skipped(string path, string reason) =>
        new() { FilePath = path, WasScanned = false, SkipReason = reason };
}
