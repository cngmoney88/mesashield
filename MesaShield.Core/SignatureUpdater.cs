using System.IO.Compression;
using System.Text.Json;

namespace MesaShield.Core;

/// <summary>
/// Downloads malware signature feeds and refreshes the local signature store.
///
/// Primary feed: MalwareBazaar by abuse.ch — a free, community threat-intelligence
/// feed of confirmed malware sample hashes (CC0 licensed).
///   Full export:   https://bazaar.abuse.ch/export/txt/sha256/full/   (zip, ~1M hashes)
///   Recent (48h):  https://bazaar.abuse.ch/export/txt/sha256/recent/ (plain text)
/// The app pulls the full export on first run, then the recent feed on a schedule.
/// </summary>
public sealed class SignatureUpdater
{
    public const string FullExportUrl = "https://bazaar.abuse.ch/export/txt/sha256/full/";
    public const string RecentExportUrl = "https://bazaar.abuse.ch/export/txt/sha256/recent/";

    private readonly HttpClient _http;
    private readonly string _signaturesDirectory;

    public SignatureUpdater(HttpClient http, string signaturesDirectory)
    {
        _http = http;
        _signaturesDirectory = signaturesDirectory;
        Directory.CreateDirectory(signaturesDirectory);
    }

    /// <summary>Download the full MalwareBazaar export. Returns the number of hashes written.</summary>
    public async Task<int> DownloadFullDatabaseAsync(
        IProgress<string>? progress = null, CancellationToken ct = default)
    {
        progress?.Report("Downloading full signature database (~50 MB)...");
        using var response = await _http.GetAsync(
            FullExportUrl, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();

        var zipPath = Path.Combine(_signaturesDirectory, "full_export.zip.tmp");
        await using (var file = File.Create(zipPath))
        {
            await response.Content.CopyToAsync(file, ct).ConfigureAwait(false);
        }

        progress?.Report("Extracting and installing signatures...");
        var count = 0;
        var targetPath = Path.Combine(_signaturesDirectory, "malwarebazaar-full.hashes");
        var tempTarget = targetPath + ".tmp";

        using (var archive = ZipFile.OpenRead(zipPath))
        {
            var entry = archive.Entries.FirstOrDefault(e => e.Name.EndsWith(".txt", StringComparison.OrdinalIgnoreCase))
                        ?? throw new InvalidDataException("Signature export did not contain a text file.");
            await using var entryStream = entry.Open();
            using var reader = new StreamReader(entryStream);
            await using var writer = new StreamWriter(tempTarget);
            while (await reader.ReadLineAsync(ct).ConfigureAwait(false) is { } line)
            {
                var normalized = SignatureDatabase.Normalize(line.Trim().Trim('"'));
                if (normalized is null) continue;
                await writer.WriteLineAsync(normalized).ConfigureAwait(false);
                count++;
            }
        }

        File.Move(tempTarget, targetPath, overwrite: true);
        File.Delete(zipPath);
        await WriteManifestAsync(ct).ConfigureAwait(false);
        progress?.Report($"Installed {count:N0} signatures.");
        return count;
    }

    /// <summary>Download the recent-additions feed and merge into an incremental file.</summary>
    public async Task<int> DownloadRecentAsync(
        IProgress<string>? progress = null, CancellationToken ct = default)
    {
        progress?.Report("Checking for new signatures...");
        var body = await _http.GetStringAsync(RecentExportUrl, ct).ConfigureAwait(false);

        var incrementalPath = Path.Combine(_signaturesDirectory, "malwarebazaar-recent.hashes");
        var existing = File.Exists(incrementalPath)
            ? new HashSet<string>(await File.ReadAllLinesAsync(incrementalPath, ct), StringComparer.Ordinal)
            : new HashSet<string>(StringComparer.Ordinal);

        var added = 0;
        foreach (var line in body.Split('\n'))
        {
            var normalized = SignatureDatabase.Normalize(line.Trim().Trim('"'));
            if (normalized is not null && existing.Add(normalized)) added++;
        }

        await File.WriteAllLinesAsync(incrementalPath, existing, ct).ConfigureAwait(false);
        await WriteManifestAsync(ct).ConfigureAwait(false);
        progress?.Report(added > 0 ? $"Added {added:N0} new signatures." : "Signatures already up to date.");
        return added;
    }

    private async Task WriteManifestAsync(CancellationToken ct)
    {
        var manifest = new SignatureManifest
        {
            LastUpdatedUtc = DateTimeOffset.UtcNow,
            Sources = { "MalwareBazaar (abuse.ch)" },
        };
        await File.WriteAllTextAsync(
            Path.Combine(_signaturesDirectory, "manifest.json"),
            JsonSerializer.Serialize(manifest, new JsonSerializerOptions { WriteIndented = true }), ct)
            .ConfigureAwait(false);
    }
}
