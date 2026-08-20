using System.Collections.Concurrent;
using System.Text.Json;

namespace MesaShield.Core;

/// <summary>Verdict from a cloud reputation lookup.</summary>
public enum ReputationVerdict { Unknown, Clean, Suspicious, Malicious }

public sealed record ReputationResult(
    ReputationVerdict Verdict, int Positives, int Total, string? Label, DateTimeOffset CheckedUtc)
{
    public static ReputationResult UnknownResult => new(ReputationVerdict.Unknown, 0, 0, null, DateTimeOffset.UtcNow);
}

/// <summary>
/// Looks up a file's SHA-256 against VirusTotal's community intelligence (v3 API).
/// This adds a second opinion from 70+ engines without us maintaining that data.
/// A key is required; without one, lookups return Unknown. Results are cached on disk
/// so repeat lookups (and the free-tier rate limit of 4 requests/min) are respected.
/// </summary>
public sealed class ReputationClient
{
    private const string ApiBase = "https://www.virustotal.com/api/v3/files/";
    private readonly HttpClient _http;
    private readonly string? _apiKey;
    private readonly int _maliciousThreshold;
    private readonly string _cachePath;
    private readonly ConcurrentDictionary<string, ReputationResult> _cache = new(StringComparer.Ordinal);
    private readonly SemaphoreSlim _saveGate = new(1, 1);

    public bool IsEnabled => !string.IsNullOrWhiteSpace(_apiKey);

    public ReputationClient(HttpClient http, string? apiKey, int maliciousThreshold, string cachePath)
    {
        _http = http;
        _apiKey = apiKey;
        _maliciousThreshold = Math.Max(1, maliciousThreshold);
        _cachePath = cachePath;
        LoadCache();
    }

    public async Task<ReputationResult> LookupAsync(string sha256, CancellationToken ct = default)
    {
        if (!IsEnabled) return ReputationResult.UnknownResult;
        if (_cache.TryGetValue(sha256, out var cached) &&
            DateTimeOffset.UtcNow - cached.CheckedUtc < TimeSpan.FromDays(7))
            return cached;

        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, ApiBase + sha256);
            request.Headers.Add("x-apikey", _apiKey);
            using var response = await _http.SendAsync(request, ct).ConfigureAwait(false);

            // 404 = VT has never seen this file. That's genuine information: unknown, not clean.
            if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
                return Cache(sha256, ReputationResult.UnknownResult);
            if (!response.IsSuccessStatusCode)
                return ReputationResult.UnknownResult;

            var result = Parse(await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false));
            return Cache(sha256, result);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException)
        {
            return ReputationResult.UnknownResult;
        }
    }

    internal ReputationResult Parse(string json)
    {
        using var doc = JsonDocument.Parse(json);
        if (!doc.RootElement.TryGetProperty("data", out var data) ||
            !data.TryGetProperty("attributes", out var attrs) ||
            !attrs.TryGetProperty("last_analysis_stats", out var stats))
            return ReputationResult.UnknownResult;

        int malicious = stats.TryGetProperty("malicious", out var m) ? m.GetInt32() : 0;
        int suspicious = stats.TryGetProperty("suspicious", out var s) ? s.GetInt32() : 0;
        int harmless = stats.TryGetProperty("harmless", out var h) ? h.GetInt32() : 0;
        int undetected = stats.TryGetProperty("undetected", out var u) ? u.GetInt32() : 0;
        var total = malicious + suspicious + harmless + undetected;

        string? label = null;
        if (attrs.TryGetProperty("popular_threat_classification", out var cls) &&
            cls.TryGetProperty("suggested_threat_label", out var lbl))
            label = lbl.GetString();

        var verdict = malicious >= _maliciousThreshold ? ReputationVerdict.Malicious
            : malicious + suspicious > 0 ? ReputationVerdict.Suspicious
            : total > 0 ? ReputationVerdict.Clean
            : ReputationVerdict.Unknown;

        return new ReputationResult(verdict, malicious + suspicious, total, label, DateTimeOffset.UtcNow);
    }

    private ReputationResult Cache(string sha256, ReputationResult result)
    {
        _cache[sha256] = result;
        _ = PersistAsync();
        return result;
    }

    private void LoadCache()
    {
        try
        {
            if (!File.Exists(_cachePath)) return;
            var loaded = JsonSerializer.Deserialize<Dictionary<string, ReputationResult>>(File.ReadAllText(_cachePath));
            if (loaded is null) return;
            foreach (var (k, v) in loaded) _cache[k] = v;
        }
        catch (Exception ex) when (ex is JsonException or IOException) { /* start with empty cache */ }
    }

    private async Task PersistAsync()
    {
        await _saveGate.WaitAsync().ConfigureAwait(false);
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_cachePath)!);
            var snapshot = _cache.ToDictionary(kv => kv.Key, kv => kv.Value);
            await File.WriteAllTextAsync(_cachePath, JsonSerializer.Serialize(snapshot)).ConfigureAwait(false);
        }
        catch (IOException) { /* cache persistence is best-effort */ }
        finally { _saveGate.Release(); }
    }
}
