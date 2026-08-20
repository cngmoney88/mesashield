using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace MesaShield.Core;

/// <summary>
/// MesaShield's lightweight pattern rule format (a YARA-inspired subset, stored as JSON).
/// A rule fires when its condition over string/hex patterns is met. Rules live in
/// *.msrules.json files in the rules directory and can be updated independently
/// of the application.
/// </summary>
public sealed record PatternRule
{
    [JsonPropertyName("name")] public required string Name { get; init; }
    [JsonPropertyName("severity")] public ThreatSeverity Severity { get; init; } = ThreatSeverity.Suspicious;

    /// <summary>Plain strings to search for (ASCII/UTF-8, case-sensitive unless nocase).</summary>
    [JsonPropertyName("strings")] public List<string> Strings { get; init; } = new();

    /// <summary>Hex byte patterns, e.g. "4D 5A 90 00". No wildcards in v1.</summary>
    [JsonPropertyName("hex")] public List<string> Hex { get; init; } = new();

    /// <summary>"any" (default) — one match fires the rule; "all" — every pattern must match.</summary>
    [JsonPropertyName("condition")] public string Condition { get; init; } = "any";

    /// <summary>Case-insensitive string matching.</summary>
    [JsonPropertyName("nocase")] public bool NoCase { get; init; }

    /// <summary>Only apply to files with one of these extensions (lower-case, with dot). Empty = all files.</summary>
    [JsonPropertyName("extensions")] public List<string> Extensions { get; init; } = new();

    [JsonPropertyName("description")] public string? Description { get; init; }
}

/// <summary>Compiled, scan-ready form of a rule.</summary>
internal sealed class CompiledRule
{
    public required PatternRule Rule { get; init; }
    public required List<byte[]> Needles { get; init; }
    public required bool RequireAll { get; init; }
    public required HashSet<string> Extensions { get; init; }
    public int LongestNeedle => Needles.Count == 0 ? 0 : Needles.Max(n => n.Length);
}

/// <summary>Loads rule files and scans byte streams against them with chunked, overlapped reads.</summary>
public sealed class PatternScanner
{
    private readonly List<CompiledRule> _rules = new();
    private int _maxNeedleLength;

    public int RuleCount => _rules.Count;

    /// <summary>The EICAR standard antivirus test string, split so MesaShield's own binaries never contain it whole.</summary>
    internal static readonly string EicarString =
        @"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

    /// <summary>Built-in rules shipped with the engine (always active).</summary>
    public static IReadOnlyList<PatternRule> BuiltInRules { get; } = new List<PatternRule>
    {
        new()
        {
            Name = "EICAR-Test-File",
            Severity = ThreatSeverity.Malicious,
            Strings = { EicarString },
            Description = "Industry-standard antivirus test file. Harmless, used to verify AV is working.",
        },
    };

    public void LoadBuiltInRules()
    {
        foreach (var rule in BuiltInRules) Add(rule);
    }

    /// <summary>Load every *.msrules.json file in a directory. Invalid files are skipped, not fatal.</summary>
    public int LoadRulesDirectory(string rulesDirectory, Action<string, Exception>? onError = null)
    {
        if (!Directory.Exists(rulesDirectory)) return 0;
        var loaded = 0;
        foreach (var file in Directory.EnumerateFiles(rulesDirectory, "*.msrules.json"))
        {
            try
            {
                var rules = JsonSerializer.Deserialize<List<PatternRule>>(File.ReadAllText(file));
                if (rules is null) continue;
                foreach (var rule in rules) { Add(rule); loaded++; }
            }
            catch (Exception ex) when (ex is JsonException or IOException)
            {
                onError?.Invoke(file, ex);
            }
        }
        return loaded;
    }

    public void Add(PatternRule rule)
    {
        var needles = new List<byte[]>();
        foreach (var s in rule.Strings)
            needles.Add(Encoding.UTF8.GetBytes(rule.NoCase ? s.ToLowerInvariant() : s));
        foreach (var h in rule.Hex)
        {
            var bytes = ParseHex(h);
            if (bytes.Length > 0) needles.Add(bytes);
        }
        if (needles.Count == 0) return;

        var compiled = new CompiledRule
        {
            Rule = rule,
            Needles = needles,
            RequireAll = string.Equals(rule.Condition, "all", StringComparison.OrdinalIgnoreCase),
            Extensions = new HashSet<string>(rule.Extensions, StringComparer.OrdinalIgnoreCase),
        };
        _rules.Add(compiled);
        _maxNeedleLength = Math.Max(_maxNeedleLength, compiled.LongestNeedle);
    }

    /// <summary>
    /// Scan a stream chunk-by-chunk with overlap so patterns spanning chunk
    /// boundaries are still found. Returns the names of rules that fired.
    /// </summary>
    public async Task<List<PatternRule>> ScanStreamAsync(
        Stream stream, string fileExtension, CancellationToken ct = default)
    {
        var applicable = _rules
            .Where(r => r.Extensions.Count == 0 || r.Extensions.Contains(fileExtension))
            .ToList();
        if (applicable.Count == 0) return new List<PatternRule>();

        // Track which needles matched, per rule, to support "all" conditions across chunks.
        var matchedPerRule = new Dictionary<CompiledRule, bool[]>();
        foreach (var rule in applicable) matchedPerRule[rule] = new bool[rule.Needles.Count];

        const int chunkSize = 4 * 1024 * 1024;
        var overlap = Math.Max(_maxNeedleLength - 1, 0);
        var buffer = new byte[chunkSize + overlap];
        var carried = 0;

        int read;
        while ((read = await stream.ReadAtLeastAsync(
                   buffer.AsMemory(carried, buffer.Length - carried), 1, false, ct)
                   .ConfigureAwait(false)) > 0)
        {
            var window = buffer.AsMemory(0, carried + read);
            SearchWindow(window.Span, applicable, matchedPerRule);

            // Carry the tail of this window forward as the head of the next.
            carried = Math.Min(overlap, window.Length);
            window.Span[^carried..].CopyTo(buffer);
        }

        var fired = new List<PatternRule>();
        foreach (var (rule, matches) in matchedPerRule)
        {
            var ok = rule.RequireAll ? matches.All(m => m) : matches.Any(m => m);
            if (ok) fired.Add(rule.Rule);
        }
        return fired;
    }

    private static void SearchWindow(
        ReadOnlySpan<byte> window, List<CompiledRule> rules, Dictionary<CompiledRule, bool[]> state)
    {
        Span<byte> lowered = default;
        byte[]? loweredArray = null;

        foreach (var rule in rules)
        {
            var haystack = window;
            if (rule.Rule.NoCase)
            {
                if (loweredArray is null)
                {
                    loweredArray = new byte[window.Length];
                    for (var i = 0; i < window.Length; i++)
                    {
                        var b = window[i];
                        loweredArray[i] = b is >= (byte)'A' and <= (byte)'Z' ? (byte)(b + 32) : b;
                    }
                    lowered = loweredArray;
                }
                haystack = lowered;
            }

            var matches = state[rule];
            for (var i = 0; i < rule.Needles.Count; i++)
            {
                if (matches[i]) continue;
                if (haystack.IndexOf(rule.Needles[i]) >= 0) matches[i] = true;
            }
        }
    }

    internal static byte[] ParseHex(string hex)
    {
        var clean = hex.Replace(" ", "").Replace("-", "");
        if (clean.Length % 2 != 0) return Array.Empty<byte>();
        try { return Convert.FromHexString(clean); }
        catch (FormatException) { return Array.Empty<byte>(); }
    }
}
