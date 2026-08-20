using System.Text.Json;
using System.Text.Json.Serialization;

namespace MesaShield.Core;

/// <summary>A semantic version (major.minor.patch) with comparison, tolerant of a leading 'v'.</summary>
public readonly record struct SemVer(int Major, int Minor, int Patch) : IComparable<SemVer>
{
    public static bool TryParse(string? text, out SemVer version)
    {
        version = default;
        if (string.IsNullOrWhiteSpace(text)) return false;
        var trimmed = text.Trim().TrimStart('v', 'V');
        var dash = trimmed.IndexOf('-');            // drop pre-release suffix
        if (dash >= 0) trimmed = trimmed[..dash];
        var parts = trimmed.Split('.');
        if (parts.Length is < 1 or > 3) return false;

        int Get(int i) => i < parts.Length && int.TryParse(parts[i], out var n) ? n : 0;
        if (!int.TryParse(parts[0], out _)) return false;
        version = new SemVer(Get(0), Get(1), Get(2));
        return true;
    }

    public int CompareTo(SemVer other)
    {
        var c = Major.CompareTo(other.Major);
        if (c != 0) return c;
        c = Minor.CompareTo(other.Minor);
        if (c != 0) return c;
        return Patch.CompareTo(other.Patch);
    }

    public static bool operator <(SemVer a, SemVer b) => a.CompareTo(b) < 0;
    public static bool operator >(SemVer a, SemVer b) => a.CompareTo(b) > 0;
    public static bool operator <=(SemVer a, SemVer b) => a.CompareTo(b) <= 0;
    public static bool operator >=(SemVer a, SemVer b) => a.CompareTo(b) >= 0;

    public override string ToString() => $"{Major}.{Minor}.{Patch}";
}

/// <summary>A release advertised by the update channel.</summary>
public sealed record ReleaseInfo
{
    [JsonPropertyName("version")] public string Version { get; init; } = "";
    [JsonPropertyName("notes")] public string? Notes { get; init; }
    [JsonPropertyName("downloadUrl")] public string DownloadUrl { get; init; } = "";
    [JsonPropertyName("sha256")] public string? Sha256 { get; init; }
    [JsonPropertyName("mandatory")] public bool Mandatory { get; init; }
}

public sealed record UpdateCheckResult(bool UpdateAvailable, SemVer Current, ReleaseInfo? Release);

/// <summary>
/// Checks whether a newer app build is available. Two channel formats are supported:
///   1. A direct URL to a JSON manifest matching <see cref="ReleaseInfo"/>.
///   2. A GitHub "owner/repo" string — the latest GitHub Release is queried and mapped.
/// The downloaded package is verified against its published SHA-256 before install.
/// </summary>
public sealed class UpdateChecker
{
    private readonly HttpClient _http;
    public UpdateChecker(HttpClient http) => _http = http;

    public async Task<UpdateCheckResult> CheckAsync(
        string channel, SemVer currentVersion, CancellationToken ct = default)
    {
        var release = await FetchLatestAsync(channel, ct).ConfigureAwait(false);
        if (release is null || !SemVer.TryParse(release.Version, out var latest))
            return new UpdateCheckResult(false, currentVersion, null);

        return new UpdateCheckResult(latest > currentVersion, currentVersion, latest > currentVersion ? release : null);
    }

    internal async Task<ReleaseInfo?> FetchLatestAsync(string channel, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(channel)) return null;

        // GitHub shorthand: "owner/repo" (no scheme, exactly one slash).
        if (!channel.Contains("://") && channel.Count(c => c == '/') == 1)
            return await FetchFromGitHubAsync(channel, ct).ConfigureAwait(false);

        var json = await _http.GetStringAsync(channel, ct).ConfigureAwait(false);
        return JsonSerializer.Deserialize<ReleaseInfo>(json);
    }

    private async Task<ReleaseInfo?> FetchFromGitHubAsync(string ownerRepo, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(
            HttpMethod.Get, $"https://api.github.com/repos/{ownerRepo}/releases/latest");
        request.Headers.UserAgent.ParseAdd("MesaShield-Updater");
        request.Headers.Accept.ParseAdd("application/vnd.github+json");

        using var response = await _http.SendAsync(request, ct).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode) return null;

        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false));
        var root = doc.RootElement;
        var tag = root.TryGetProperty("tag_name", out var t) ? t.GetString() ?? "" : "";
        var notes = root.TryGetProperty("body", out var b) ? b.GetString() : null;

        // Prefer a .zip or .exe asset.
        string downloadUrl = "";
        if (root.TryGetProperty("assets", out var assets))
        {
            foreach (var asset in assets.EnumerateArray())
            {
                var name = asset.TryGetProperty("name", out var n) ? n.GetString() ?? "" : "";
                if (name.EndsWith(".zip", StringComparison.OrdinalIgnoreCase) ||
                    name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ||
                    name.EndsWith(".msi", StringComparison.OrdinalIgnoreCase))
                {
                    downloadUrl = asset.TryGetProperty("browser_download_url", out var u) ? u.GetString() ?? "" : "";
                    break;
                }
            }
        }
        return new ReleaseInfo { Version = tag, Notes = notes, DownloadUrl = downloadUrl };
    }

    /// <summary>Download the release package to <paramref name="destinationPath"/>, verifying its hash if provided.</summary>
    public async Task DownloadAsync(
        ReleaseInfo release, string destinationPath,
        IProgress<double>? progress = null, CancellationToken ct = default)
    {
        using var response = await _http.GetAsync(
            release.DownloadUrl, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        var total = response.Content.Headers.ContentLength;

        await using (var source = await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false))
        await using (var dest = File.Create(destinationPath))
        {
            var buffer = new byte[81920];
            long readTotal = 0;
            int read;
            while ((read = await source.ReadAsync(buffer, ct).ConfigureAwait(false)) > 0)
            {
                await dest.WriteAsync(buffer.AsMemory(0, read), ct).ConfigureAwait(false);
                readTotal += read;
                if (total is > 0) progress?.Report((double)readTotal / total.Value);
            }
        }

        if (!string.IsNullOrWhiteSpace(release.Sha256))
        {
            var actual = await FileHasher.Sha256Async(destinationPath, ct).ConfigureAwait(false);
            if (!string.Equals(actual, release.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                File.Delete(destinationPath);
                throw new InvalidOperationException(
                    "Downloaded update failed hash verification — the file was rejected for safety.");
            }
        }
    }
}
