using System.Text.Json;
using System.Text.Json.Serialization;

namespace MesaShield.Core;

/// <summary>
/// In-memory SHA-256 signature database. Signatures are stored on disk as plain text
/// files (one lower-case hex hash per line, '#' comments allowed) inside a signatures
/// directory, plus a manifest.json with metadata. MalwareBazaar's full export
/// (~1M hashes) loads in a couple of seconds and sits in roughly 100 MB of RAM,
/// which is in line with commercial AV engines.
/// </summary>
public sealed class SignatureDatabase
{
    private readonly HashSet<string> _hashes = new(StringComparer.Ordinal);
    private readonly Dictionary<string, string> _names = new(StringComparer.Ordinal);

    public int Count => _hashes.Count;
    public DateTimeOffset? LastUpdatedUtc { get; private set; }
    public string? SignaturesDirectory { get; private set; }

    /// <summary>Load every *.hashes file in the given directory. Safe to call again to reload.</summary>
    public async Task LoadAsync(string signaturesDirectory, CancellationToken ct = default)
    {
        SignaturesDirectory = signaturesDirectory;
        _hashes.Clear();
        _names.Clear();

        if (!Directory.Exists(signaturesDirectory))
        {
            Directory.CreateDirectory(signaturesDirectory);
            return;
        }

        foreach (var file in Directory.EnumerateFiles(signaturesDirectory, "*.hashes"))
        {
            await foreach (var line in ReadLinesAsync(file, ct))
            {
                var trimmed = line.Trim();
                if (trimmed.Length == 0 || trimmed[0] == '#') continue;

                // Optional format: "<sha256>\t<threat name>"
                var tab = trimmed.IndexOf('\t');
                if (tab > 0)
                {
                    var hash = Normalize(trimmed[..tab]);
                    if (hash is null) continue;
                    _hashes.Add(hash);
                    _names[hash] = trimmed[(tab + 1)..].Trim();
                }
                else
                {
                    var hash = Normalize(trimmed);
                    if (hash is not null) _hashes.Add(hash);
                }
            }
        }

        var manifestPath = Path.Combine(signaturesDirectory, "manifest.json");
        if (File.Exists(manifestPath))
        {
            try
            {
                var manifest = JsonSerializer.Deserialize<SignatureManifest>(
                    await File.ReadAllTextAsync(manifestPath, ct));
                LastUpdatedUtc = manifest?.LastUpdatedUtc;
            }
            catch (JsonException) { /* corrupt manifest is non-fatal */ }
        }
    }

    /// <summary>True if this SHA-256 (lower-case hex) is known malware.</summary>
    public bool Contains(string sha256Hex) => _hashes.Contains(sha256Hex);

    /// <summary>Threat name for a known hash, if the feed provided one.</summary>
    public string ThreatNameFor(string sha256Hex) =>
        _names.TryGetValue(sha256Hex, out var name) ? name : "Known malware (signature match)";

    internal static string? Normalize(string candidate)
    {
        if (candidate.Length != 64) return null;
        foreach (var c in candidate)
            if (!char.IsAsciiHexDigit(c)) return null;
        return candidate.ToLowerInvariant();
    }

    private static async IAsyncEnumerable<string> ReadLinesAsync(
        string path, [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
    {
        using var reader = new StreamReader(path);
        while (await reader.ReadLineAsync(ct).ConfigureAwait(false) is { } line)
            yield return line;
    }
}

public sealed record SignatureManifest
{
    [JsonPropertyName("lastUpdatedUtc")] public DateTimeOffset? LastUpdatedUtc { get; init; }
    [JsonPropertyName("sources")] public List<string> Sources { get; init; } = new();
}
