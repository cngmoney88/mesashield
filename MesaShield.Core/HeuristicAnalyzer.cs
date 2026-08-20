using System.Buffers.Binary;
using System.IO.Compression;

namespace MesaShield.Core;

/// <summary>
/// Heuristic checks: things that are not proof of malware on their own but are
/// strong warning signs. Findings are reported as Suspicious (never auto-quarantined)
/// unless several independent signals stack up.
/// </summary>
public sealed class HeuristicAnalyzer
{
    private static readonly HashSet<string> ExecutableExtensions = new(StringComparer.OrdinalIgnoreCase)
    { ".exe", ".dll", ".scr", ".com", ".pif", ".cpl", ".sys" };

    private static readonly HashSet<string> ScriptExtensions = new(StringComparer.OrdinalIgnoreCase)
    { ".js", ".jse", ".vbs", ".vbe", ".wsf", ".hta", ".ps1", ".psm1", ".bat", ".cmd" };

    private static readonly HashSet<string> DecoyExtensions = new(StringComparer.OrdinalIgnoreCase)
    { ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".jpeg", ".png", ".txt", ".mp3", ".mp4", ".zip" };

    private static readonly string[] SuspiciousScriptMarkers =
    {
        "-EncodedCommand", "-enc ", "FromBase64String", "DownloadString(", "DownloadFile(",
        "Invoke-Expression", "IEX(", "iex (", "WScript.Shell", "cmd /c powershell",
        "bypass -nop", "-WindowStyle Hidden", "chrw(", "eval(unescape(", "String.fromCharCode(",
        "schtasks /create", "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "vssadmin delete shadows", "wbadmin delete catalog", "bcdedit /set {default} recoveryenabled no",
    };

    /// <summary>Run all heuristics against a file. Buffer holds up to the first 8 MB of content.</summary>
    public List<ThreatFinding> Analyze(string filePath, ReadOnlySpan<byte> head, long fileLength)
    {
        var findings = new List<ThreatFinding>();
        var fileName = Path.GetFileName(filePath);
        var extension = Path.GetExtension(filePath);

        CheckDoubleExtension(filePath, fileName, extension, findings);
        CheckExtensionMismatch(filePath, extension, head, findings);

        if (ExecutableExtensions.Contains(extension) && IsPeFile(head))
            CheckPeAnomalies(filePath, head, fileLength, findings);

        if (ScriptExtensions.Contains(extension))
            CheckScriptContent(filePath, head, findings);

        if (extension is ".docm" or ".xlsm" or ".pptm" || IsOfficeWithMacros(filePath, extension))
            findings.Add(Suspicious(filePath, "Heur.OfficeMacro",
                "Office document contains macros. Only open it if you trust the sender."));

        return findings;
    }

    private static void CheckDoubleExtension(
        string filePath, string fileName, string extension, List<ThreatFinding> findings)
    {
        // "invoice.pdf.exe" — an executable dressed up as a document.
        if (!ExecutableExtensions.Contains(extension) && !ScriptExtensions.Contains(extension)) return;
        var withoutLast = Path.GetFileNameWithoutExtension(fileName);
        var innerExt = Path.GetExtension(withoutLast);
        if (innerExt.Length > 1 && DecoyExtensions.Contains(innerExt))
        {
            findings.Add(new ThreatFinding
            {
                FilePath = filePath,
                ThreatName = "Heur.DoubleExtension",
                Method = DetectionMethod.Heuristic,
                Severity = ThreatSeverity.Malicious,
                Detail = $"Executable disguised as a {innerExt} file (\"{fileName}\"). This is a classic malware delivery trick.",
            });
        }
    }

    private static void CheckExtensionMismatch(
        string filePath, string extension, ReadOnlySpan<byte> head, List<ThreatFinding> findings)
    {
        // A "document" or "image" that is actually a Windows executable.
        if (DecoyExtensions.Contains(extension) && IsPeFile(head))
        {
            findings.Add(new ThreatFinding
            {
                FilePath = filePath,
                ThreatName = "Heur.DisguisedExecutable",
                Method = DetectionMethod.Heuristic,
                Severity = ThreatSeverity.Malicious,
                Detail = $"File claims to be {extension} but is actually a Windows executable.",
            });
        }
    }

    private void CheckPeAnomalies(
        string filePath, ReadOnlySpan<byte> head, long fileLength, List<ThreatFinding> findings)
    {
        var signals = new List<string>();

        // High entropy over the body of the file suggests packing/encryption.
        if (head.Length >= 64 * 1024)
        {
            var entropy = ShannonEntropy(head[1024..]);
            if (entropy > 7.4) signals.Add($"very high entropy ({entropy:F2}/8.00) — likely packed or encrypted");
        }

        if (TryGetPeHeaderOffset(head, out var peOffset) && peOffset + 24 <= head.Length)
        {
            var numberOfSections = BinaryPrimitives.ReadUInt16LittleEndian(head[(peOffset + 6)..]);
            if (numberOfSections is 0 or > 20) signals.Add($"abnormal section count ({numberOfSections})");
        }

        if (fileLength < 20 * 1024 && signals.Count > 0)
            signals.Add("unusually small executable");

        if (signals.Count > 0)
        {
            findings.Add(Suspicious(filePath, "Heur.SuspiciousExecutable", string.Join("; ", signals)));
        }
    }

    private static void CheckScriptContent(
        string filePath, ReadOnlySpan<byte> head, List<ThreatFinding> findings)
    {
        var text = System.Text.Encoding.UTF8.GetString(head);
        var hits = SuspiciousScriptMarkers
            .Where(marker => text.Contains(marker, StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (hits.Count == 0) return;

        // Destructive/ransomware markers are treated as malicious outright.
        var destructive = hits.Any(h =>
            h.StartsWith("vssadmin", StringComparison.OrdinalIgnoreCase) ||
            h.StartsWith("wbadmin", StringComparison.OrdinalIgnoreCase) ||
            h.StartsWith("bcdedit", StringComparison.OrdinalIgnoreCase));

        findings.Add(new ThreatFinding
        {
            FilePath = filePath,
            ThreatName = destructive ? "Heur.DestructiveScript" : "Heur.SuspiciousScript",
            Method = DetectionMethod.Heuristic,
            Severity = destructive || hits.Count >= 3 ? ThreatSeverity.Malicious : ThreatSeverity.Suspicious,
            Detail = $"Script contains {hits.Count} suspicious command pattern(s): {string.Join(", ", hits.Take(5))}",
        });
    }

    private static bool IsOfficeWithMacros(string filePath, string extension)
    {
        // Modern Office files are zip containers; macros live in vbaProject.bin.
        if (extension is not (".docx" or ".xlsx" or ".pptx")) return false;
        try
        {
            using var archive = ZipFile.OpenRead(filePath);
            return archive.Entries.Any(e =>
                e.FullName.EndsWith("vbaProject.bin", StringComparison.OrdinalIgnoreCase));
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    internal static bool IsPeFile(ReadOnlySpan<byte> head) =>
        head.Length >= 2 && head[0] == (byte)'M' && head[1] == (byte)'Z';

    private static bool TryGetPeHeaderOffset(ReadOnlySpan<byte> head, out int offset)
    {
        offset = 0;
        if (head.Length < 0x40) return false;
        var e_lfanew = BinaryPrimitives.ReadInt32LittleEndian(head[0x3C..]);
        if (e_lfanew <= 0 || e_lfanew + 4 > head.Length) return false;
        if (head[e_lfanew] != 'P' || head[e_lfanew + 1] != 'E') return false;
        offset = e_lfanew;
        return true;
    }

    public static double ShannonEntropy(ReadOnlySpan<byte> data)
    {
        if (data.Length == 0) return 0;
        Span<int> counts = stackalloc int[256];
        foreach (var b in data) counts[b]++;
        double entropy = 0, length = data.Length;
        foreach (var count in counts)
        {
            if (count == 0) continue;
            var p = count / length;
            entropy -= p * Math.Log2(p);
        }
        return entropy;
    }

    private static ThreatFinding Suspicious(string filePath, string name, string detail) => new()
    {
        FilePath = filePath,
        ThreatName = name,
        Method = DetectionMethod.Heuristic,
        Severity = ThreatSeverity.Suspicious,
        Detail = detail,
    };
}
