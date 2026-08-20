using System.Text;
using MesaShield.Core;
using Xunit;

namespace MesaShield.Tests;

public sealed class QuarantineTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("mesashield-quarantine-").FullName;

    [Fact]
    public async Task Quarantine_Removes_Original_And_Restore_Recovers_Exact_Bytes()
    {
        var original = Path.Combine(_dir, "threat.bin");
        var content = new byte[123_457];
        Random.Shared.NextBytes(content);
        await File.WriteAllBytesAsync(original, content);

        var manager = new QuarantineManager(Path.Combine(_dir, "quarantine"));
        var finding = new ThreatFinding
        {
            FilePath = original,
            ThreatName = "Test.Threat",
            Method = DetectionMethod.SignatureHash,
            Severity = ThreatSeverity.Malicious,
            Sha256 = "abc",
        };

        var entry = await manager.QuarantineAsync(finding);
        Assert.NotNull(entry);
        Assert.False(File.Exists(original));                       // original is gone
        var stored = Path.Combine(_dir, "quarantine", entry!.Id + ".msq");
        Assert.True(File.Exists(stored));                          // encrypted copy exists
        Assert.False((await File.ReadAllBytesAsync(stored)).AsSpan().SequenceEqual(content)); // and is not plaintext

        Assert.True(await manager.RestoreAsync(entry.Id));
        Assert.True(File.Exists(original));
        Assert.Equal(content, await File.ReadAllBytesAsync(original)); // byte-exact restore
    }

    [Fact]
    public async Task Delete_Removes_Entry_Permanently()
    {
        var original = Path.Combine(_dir, "junk.bin");
        await File.WriteAllBytesAsync(original, Encoding.ASCII.GetBytes("bad file"));

        var manager = new QuarantineManager(Path.Combine(_dir, "quarantine"));
        var entry = await manager.QuarantineAsync(new ThreatFinding
        {
            FilePath = original,
            ThreatName = "Test.Threat",
            Method = DetectionMethod.Pattern,
            Severity = ThreatSeverity.Malicious,
        });

        Assert.True(await manager.DeleteAsync(entry!.Id));
        Assert.Empty(await manager.ListAsync());
        Assert.False(File.Exists(Path.Combine(_dir, "quarantine", entry.Id + ".msq")));
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { /* best effort */ }
    }
}
