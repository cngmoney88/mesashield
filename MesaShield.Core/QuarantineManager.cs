using System.Security.Cryptography;
using System.Text.Json;

namespace MesaShield.Core;

/// <summary>
/// Quarantine: neutralizes a detected file by AES-encrypting it into the quarantine
/// store and deleting the original. Encryption (rather than just moving) guarantees
/// the file can never execute from quarantine, can't be re-detected by scans, and
/// can still be restored exactly if it was a false positive.
/// </summary>
public sealed class QuarantineManager
{
    private readonly string _quarantineDirectory;
    private readonly string _indexPath;
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    public QuarantineManager(string quarantineDirectory)
    {
        _quarantineDirectory = quarantineDirectory;
        _indexPath = Path.Combine(quarantineDirectory, "index.json");
        Directory.CreateDirectory(quarantineDirectory);
    }

    public sealed record QuarantineEntry
    {
        public required string Id { get; init; }
        public required string OriginalPath { get; init; }
        public required string ThreatName { get; init; }
        public required string Sha256 { get; init; }
        public required long OriginalSize { get; init; }
        public required DateTimeOffset QuarantinedAt { get; init; }
        public required string KeyBase64 { get; init; }
        public required string IvBase64 { get; init; }
        public string? Detail { get; init; }
    }

    /// <summary>Encrypt the file into quarantine and remove the original. Returns the entry, or null if the file vanished.</summary>
    public async Task<QuarantineEntry?> QuarantineAsync(ThreatFinding finding, CancellationToken ct = default)
    {
        if (!File.Exists(finding.FilePath)) return null;

        var id = Guid.NewGuid().ToString("N");
        var storedPath = Path.Combine(_quarantineDirectory, id + ".msq");
        var originalSize = new FileInfo(finding.FilePath).Length;

        using var aes = Aes.Create();
        aes.GenerateKey();
        aes.GenerateIV();

        await using (var source = new FileStream(
            finding.FilePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
        await using (var destination = new FileStream(storedPath, FileMode.CreateNew, FileAccess.Write))
        await using (var crypto = new CryptoStream(destination, aes.CreateEncryptor(), CryptoStreamMode.Write))
        {
            await source.CopyToAsync(crypto, ct).ConfigureAwait(false);
        }

        // Only delete the original once the encrypted copy is safely written.
        File.SetAttributes(finding.FilePath, FileAttributes.Normal);
        File.Delete(finding.FilePath);

        var entry = new QuarantineEntry
        {
            Id = id,
            OriginalPath = finding.FilePath,
            ThreatName = finding.ThreatName,
            Sha256 = finding.Sha256 ?? "",
            OriginalSize = originalSize,
            QuarantinedAt = DateTimeOffset.UtcNow,
            KeyBase64 = Convert.ToBase64String(aes.Key),
            IvBase64 = Convert.ToBase64String(aes.IV),
            Detail = finding.Detail,
        };

        var index = await LoadIndexAsync(ct).ConfigureAwait(false);
        index.Add(entry);
        await SaveIndexAsync(index, ct).ConfigureAwait(false);
        return entry;
    }

    /// <summary>Restore a quarantined file to its original location (false-positive recovery).</summary>
    public async Task<bool> RestoreAsync(string id, CancellationToken ct = default)
    {
        var index = await LoadIndexAsync(ct).ConfigureAwait(false);
        var entry = index.FirstOrDefault(e => e.Id == id);
        if (entry is null) return false;

        var storedPath = Path.Combine(_quarantineDirectory, id + ".msq");
        if (!File.Exists(storedPath)) return false;

        var restorePath = entry.OriginalPath;
        Directory.CreateDirectory(Path.GetDirectoryName(restorePath)!);
        if (File.Exists(restorePath))
            restorePath = UniquePath(restorePath);

        using var aes = Aes.Create();
        aes.Key = Convert.FromBase64String(entry.KeyBase64);
        aes.IV = Convert.FromBase64String(entry.IvBase64);

        await using (var source = new FileStream(storedPath, FileMode.Open, FileAccess.Read))
        await using (var crypto = new CryptoStream(source, aes.CreateDecryptor(), CryptoStreamMode.Read))
        await using (var destination = new FileStream(restorePath, FileMode.CreateNew, FileAccess.Write))
        {
            await crypto.CopyToAsync(destination, ct).ConfigureAwait(false);
        }

        File.Delete(storedPath);
        index.RemoveAll(e => e.Id == id);
        await SaveIndexAsync(index, ct).ConfigureAwait(false);
        return true;
    }

    /// <summary>Permanently delete a quarantined file.</summary>
    public async Task<bool> DeleteAsync(string id, CancellationToken ct = default)
    {
        var index = await LoadIndexAsync(ct).ConfigureAwait(false);
        if (index.RemoveAll(e => e.Id == id) == 0) return false;

        var storedPath = Path.Combine(_quarantineDirectory, id + ".msq");
        if (File.Exists(storedPath)) File.Delete(storedPath);
        await SaveIndexAsync(index, ct).ConfigureAwait(false);
        return true;
    }

    public async Task<IReadOnlyList<QuarantineEntry>> ListAsync(CancellationToken ct = default) =>
        await LoadIndexAsync(ct).ConfigureAwait(false);

    private async Task<List<QuarantineEntry>> LoadIndexAsync(CancellationToken ct)
    {
        if (!File.Exists(_indexPath)) return new List<QuarantineEntry>();
        try
        {
            await using var stream = File.OpenRead(_indexPath);
            return await JsonSerializer.DeserializeAsync<List<QuarantineEntry>>(stream, JsonOptions, ct)
                       .ConfigureAwait(false) ?? new List<QuarantineEntry>();
        }
        catch (JsonException)
        {
            return new List<QuarantineEntry>();
        }
    }

    private async Task SaveIndexAsync(List<QuarantineEntry> index, CancellationToken ct)
    {
        var tempPath = _indexPath + ".tmp";
        await using (var stream = File.Create(tempPath))
        {
            await JsonSerializer.SerializeAsync(stream, index, JsonOptions, ct).ConfigureAwait(false);
        }
        File.Move(tempPath, _indexPath, overwrite: true);
    }

    private static string UniquePath(string path)
    {
        var directory = Path.GetDirectoryName(path)!;
        var name = Path.GetFileNameWithoutExtension(path);
        var extension = Path.GetExtension(path);
        for (var i = 1; ; i++)
        {
            var candidate = Path.Combine(directory, $"{name} (restored {i}){extension}");
            if (!File.Exists(candidate)) return candidate;
        }
    }
}
