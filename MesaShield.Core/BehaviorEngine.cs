using System.Collections.Concurrent;

namespace MesaShield.Core;

/// <summary>A behavioral alert (not tied to a single file signature).</summary>
public sealed record BehaviorAlert
{
    public required string Kind { get; init; }
    public required ThreatSeverity Severity { get; init; }
    public required string Message { get; init; }
    public int? SuspectProcessId { get; init; }
    public IReadOnlyList<string> AffectedFiles { get; init; } = Array.Empty<string>();
    public DateTimeOffset At { get; init; } = DateTimeOffset.UtcNow;
}

/// <summary>
/// Detects ransomware-style behavior by watching the *rate and shape* of file changes
/// rather than any file's contents. Two independent signals:
///
///   1. Canary files — decoy files seeded in common folders. Any modification to a
///      canary is a near-certain ransomware indicator (normal software never touches them).
///   2. Mass-modification burst — a flood of file writes in a short window, especially
///      when the new content has high entropy (encrypted) or filenames gain a new
///      uniform extension (.locked, .encrypted, etc.).
///
/// The engine is platform-agnostic and unit-tested; the Windows layer feeds it file
/// events and acts on alerts (kill the offending process, alert the user).
/// </summary>
public sealed class BehaviorEngine
{
    private readonly HashSet<string> _canaryFiles = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentQueue<(DateTimeOffset When, string Path)> _recentModifications = new();
    private readonly object _evalGate = new();

    /// <summary>Number of modifications within the window that trips the mass-modification alert.</summary>
    public int BurstThreshold { get; init; } = 40;
    public TimeSpan BurstWindow { get; init; } = TimeSpan.FromSeconds(10);

    /// <summary>Suspicious extensions ransomware commonly appends.</summary>
    private static readonly HashSet<string> RansomExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".locked", ".encrypted", ".enc", ".crypt", ".crypted", ".cryp1", ".locky", ".zepto",
        ".cerber", ".osiris", ".wcry", ".wncry", ".wannacry", ".ryk", ".ryuk", ".conti",
        ".lockbit", ".blackcat", ".akira", ".ecc", ".ezz", ".exx", ".pays", ".payms",
    };

    private static readonly string[] RansomNoteMarkers =
    {
        "readme", "decrypt", "how_to", "how-to", "recover", "restore", "ransom", "unlock",
    };

    public event Action<BehaviorAlert>? AlertRaised;

    public IReadOnlyCollection<string> CanaryFiles => _canaryFiles;

    /// <summary>Register a canary file so modifications to it trigger an immediate alert.</summary>
    public void RegisterCanary(string path) => _canaryFiles.Add(Path.GetFullPath(path));

    /// <summary>
    /// Feed a file-change event. Returns an alert if this event (in context) is
    /// judged malicious, and also raises <see cref="AlertRaised"/>.
    /// </summary>
    public BehaviorAlert? OnFileChanged(string path, DateTimeOffset when, int? processId = null, double? newContentEntropy = null)
    {
        // Signal 1: canary touched.
        if (_canaryFiles.Contains(Path.GetFullPath(path)))
        {
            return Raise(new BehaviorAlert
            {
                Kind = "Ransomware.CanaryTriggered",
                Severity = ThreatSeverity.Malicious,
                Message = $"A protected decoy file was modified ({Path.GetFileName(path)}). This is a strong ransomware indicator.",
                SuspectProcessId = processId,
                AffectedFiles = new[] { path },
            });
        }

        var extension = Path.GetExtension(path);
        var name = Path.GetFileNameWithoutExtension(path).ToLowerInvariant();

        // Signal 2a: a file gained a known ransomware extension.
        if (RansomExtensions.Contains(extension))
        {
            return Raise(new BehaviorAlert
            {
                Kind = "Ransomware.KnownExtension",
                Severity = ThreatSeverity.Malicious,
                Message = $"A file was rewritten with a ransomware extension ({extension}).",
                SuspectProcessId = processId,
                AffectedFiles = new[] { path },
            });
        }

        // Signal 2b: a ransom note appeared.
        if (RansomNoteMarkers.Any(marker => name.Contains(marker)) &&
            extension is ".txt" or ".html" or ".hta")
        {
            // A single ransom-note-like file is only suspicious on its own.
            Raise(new BehaviorAlert
            {
                Kind = "Ransomware.PossibleNote",
                Severity = ThreatSeverity.Suspicious,
                Message = $"A file resembling a ransom note appeared ({Path.GetFileName(path)}).",
                SuspectProcessId = processId,
                AffectedFiles = new[] { path },
            });
        }

        // Signal 2c: mass-modification burst.
        var now = when;
        _recentModifications.Enqueue((now, path));
        return EvaluateBurst(now, processId, newContentEntropy);
    }

    private BehaviorAlert? EvaluateBurst(DateTimeOffset now, int? processId, double? entropy)
    {
        lock (_evalGate)
        {
            var cutoff = now - BurstWindow;
            while (_recentModifications.TryPeek(out var head) && head.When < cutoff)
                _recentModifications.TryDequeue(out _);

            var window = _recentModifications.ToArray();
            if (window.Length < BurstThreshold) return null;

            // High-entropy content in a burst is the encryption fingerprint.
            var highEntropy = entropy is >= 7.5;
            var distinctFiles = window.Select(e => e.Path).Distinct().Count();

            // Reset so we don't fire repeatedly for the same burst.
            _recentModifications.Clear();

            return Raise(new BehaviorAlert
            {
                Kind = highEntropy ? "Ransomware.EncryptionBurst" : "Ransomware.MassModification",
                Severity = ThreatSeverity.Malicious,
                Message = highEntropy
                    ? $"{distinctFiles} files rewritten with encrypted (high-entropy) content in under {BurstWindow.TotalSeconds:F0}s — active ransomware behavior."
                    : $"{distinctFiles} files modified in under {BurstWindow.TotalSeconds:F0}s — abnormal mass-modification.",
                SuspectProcessId = processId,
                AffectedFiles = window.Select(e => e.Path).Distinct().Take(20).ToList(),
            });
        }
    }

    private BehaviorAlert Raise(BehaviorAlert alert)
    {
        AlertRaised?.Invoke(alert);
        return alert;
    }
}
