using System.Security.Cryptography;

namespace MesaShield.Core;

/// <summary>Streaming file hashing so large files never load fully into memory.</summary>
public static class FileHasher
{
    /// <summary>Compute the SHA-256 of a file, returned as lower-case hex.</summary>
    public static async Task<string> Sha256Async(string path, CancellationToken ct = default)
    {
        await using var stream = new FileStream(
            path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete,
            bufferSize: 1 << 20, options: FileOptions.Asynchronous | FileOptions.SequentialScan);
        using var sha = SHA256.Create();
        var hash = await sha.ComputeHashAsync(stream, ct).ConfigureAwait(false);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    /// <summary>Compute the SHA-256 of an in-memory buffer (used for archive entries).</summary>
    public static string Sha256(ReadOnlySpan<byte> data)
    {
        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(data, hash);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}
