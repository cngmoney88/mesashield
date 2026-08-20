using System.Buffers.Binary;

namespace MesaShield.Core.Ml;

/// <summary>
/// Extracts a fixed-order vector of static features from a Windows PE (exe/dll) — the same
/// kind of features research malware classifiers use (entropy, header fields, section stats,
/// size buckets). Runs offline on the file's own bytes; nothing is uploaded. The feature
/// order here MUST match the order the training pipeline uses to produce the model.
/// </summary>
public static class PeFeatureExtractor
{
    /// <summary>Canonical feature order. Keep in sync with train_classifier.py.</summary>
    public static readonly string[] FeatureNames =
    {
        "size_log",              // log10(file size)
        "entropy_overall",       // Shannon entropy of the (head of the) file
        "is_pe",                 // 1 if MZ/PE
        "num_sections",          // PE section count
        "high_entropy",          // 1 if entropy > 7.2 (packed/encrypted)
        "has_tls",               // reserved: TLS directory present (approx)
        "header_size_ratio",     // headers size / file size (approx via e_lfanew)
        "printable_ratio",       // fraction of printable bytes in head
        "null_ratio",            // fraction of 0x00 bytes in head
        "imports_hint",          // count of common suspicious import strings present
    };

    private static readonly string[] SuspiciousImports =
    {
        "VirtualAlloc", "VirtualProtect", "WriteProcessMemory", "CreateRemoteThread",
        "LoadLibrary", "GetProcAddress", "WinExec", "ShellExecute", "URLDownloadToFile",
        "CryptEncrypt", "RegSetValue", "SetWindowsHookEx", "IsDebuggerPresent",
    };

    public static double[] Extract(ReadOnlySpan<byte> head, long fileLength)
    {
        var isPe = head.Length >= 2 && head[0] == (byte)'M' && head[1] == (byte)'Z';
        var entropy = head.Length > 256 ? HeuristicAnalyzer.ShannonEntropy(head) : 0;

        int numSections = 0;
        double headerRatio = 0;
        if (isPe && head.Length >= 0x40)
        {
            var eLfanew = BinaryPrimitives.ReadInt32LittleEndian(head[0x3C..]);
            if (eLfanew > 0 && eLfanew + 8 <= head.Length && head[eLfanew] == 'P' && head[eLfanew + 1] == 'E')
            {
                numSections = BinaryPrimitives.ReadUInt16LittleEndian(head[(eLfanew + 6)..]);
                headerRatio = fileLength > 0 ? Math.Min(1.0, eLfanew / (double)fileLength) : 0;
            }
        }

        int printable = 0, nulls = 0;
        foreach (var b in head)
        {
            if (b == 0) nulls++;
            else if (b is >= 32 and < 127) printable++;
        }
        double headLen = Math.Max(head.Length, 1);

        // Cheap "imports" proxy: look for known API names as ASCII in the head.
        var text = System.Text.Encoding.ASCII.GetString(head);
        int importHits = SuspiciousImports.Count(s => text.Contains(s, StringComparison.Ordinal));

        return new[]
        {
            Math.Log10(Math.Max(fileLength, 1)),
            entropy,
            isPe ? 1.0 : 0.0,
            Math.Min(numSections, 64),
            entropy > 7.2 ? 1.0 : 0.0,
            0.0, // has_tls placeholder (kept for model-format stability)
            headerRatio,
            printable / headLen,
            nulls / headLen,
            Math.Min(importHits, 16),
        };
    }
}
