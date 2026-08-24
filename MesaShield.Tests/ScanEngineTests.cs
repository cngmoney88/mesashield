using System.Text;
using MesaShield.Core;
using Xunit;

namespace MesaShield.Tests;

public sealed class ScanEngineTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("mesashield-tests-").FullName;

    private ScanEngine CreateEngine(SignatureDatabase? signatures = null)
    {
        var patterns = new PatternScanner();
        patterns.LoadBuiltInRules();
        return new ScanEngine(signatures ?? new SignatureDatabase(), patterns, new HeuristicAnalyzer());
    }

    private string WriteFile(string name, byte[] content)
    {
        var path = Path.Combine(_dir, name);
        File.WriteAllBytes(path, content);
        return path;
    }

    // EICAR is assembled at runtime from PatternScanner so no MesaShield source file
    // or test binary contains the test string in scannable form on its own.
    private static byte[] EicarBytes() => Encoding.ASCII.GetBytes(
        typeof(PatternScanner)
            .GetField("EicarString", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)!
            .GetValue(null)!.ToString()!);

    [Fact]
    public async Task Detects_Eicar_Test_File()
    {
        var path = WriteFile("eicar.com", EicarBytes());
        var result = await CreateEngine().ScanFileAsync(path, new ScanOptions());

        Assert.False(result.IsClean);
        Assert.Contains(result.Findings, f => f.ThreatName == "EICAR-Test-File" && f.Severity == ThreatSeverity.Malicious);
    }

    [Fact]
    public async Task Signed_Program_Is_Not_Quarantined_On_A_Heuristic_Guess()
    {
        // A disguised-executable heuristic normally fires Malicious (which triggers auto-quarantine).
        var path = WriteFile("invoice.pdf.exe", new byte[] { 0x4D, 0x5A, 0, 0, 0, 0, 0, 0 });

        var unsigned = CreateEngine();
        var r1 = await unsigned.ScanFileAsync(path, new ScanOptions());
        Assert.Contains(r1.Findings, f => f.Method == DetectionMethod.Heuristic && f.Severity == ThreatSeverity.Malicious);

        // With a trusted signature, the same finding must be downgraded to Suspicious — never deleted.
        var signed = CreateEngine();
        signed.IsTrustedSigned = _ => true;
        var r2 = await signed.ScanFileAsync(path, new ScanOptions());
        Assert.DoesNotContain(r2.Findings, f => f.Severity == ThreatSeverity.Malicious);
        Assert.Contains(r2.Findings, f => f.Method == DetectionMethod.Heuristic && f.Severity == ThreatSeverity.Suspicious);
    }

    [Fact]
    public async Task Signed_File_Is_Still_Quarantined_On_A_Definitive_Signature_Hit()
    {
        // Trust must NOT shield a file that is a confirmed known-malware hash match.
        var path = WriteFile("eicar-signed.com", EicarBytes());
        var engine = CreateEngine();
        engine.IsTrustedSigned = _ => true;   // pretend it's signed
        var result = await engine.ScanFileAsync(path, new ScanOptions());
        Assert.Contains(result.Findings, f => f.ThreatName == "EICAR-Test-File" && f.Severity == ThreatSeverity.Malicious);
    }

    [Fact]
    public async Task Detects_Eicar_Across_Chunk_Boundary()
    {
        // Bury EICAR deep in a large file to exercise the chunked/overlapped stream scan.
        var padding = new byte[5 * 1024 * 1024];
        Random.Shared.NextBytes(padding);
        var eicar = EicarBytes();
        var content = padding.Concat(eicar).Concat(padding).ToArray();
        var path = WriteFile("buried.bin", content);

        var result = await CreateEngine().ScanFileAsync(path, new ScanOptions());
        Assert.Contains(result.Findings, f => f.ThreatName == "EICAR-Test-File");
    }

    [Fact]
    public async Task Detects_Known_Hash_Signature()
    {
        var content = Encoding.ASCII.GetBytes("pretend malware body for signature test");
        var path = WriteFile("sample.bin", content);
        var sha256 = await FileHasher.Sha256Async(path);

        var sigDir = Path.Combine(_dir, "sigs");
        Directory.CreateDirectory(sigDir);
        await File.WriteAllTextAsync(Path.Combine(sigDir, "test.hashes"), $"{sha256}\tTestThreat.MesaShield\n");

        var signatures = new SignatureDatabase();
        await signatures.LoadAsync(sigDir);
        Assert.Equal(1, signatures.Count);

        var result = await CreateEngine(signatures).ScanFileAsync(path, new ScanOptions());
        var finding = Assert.Single(result.Findings);
        Assert.Equal(DetectionMethod.SignatureHash, finding.Method);
        Assert.Equal("TestThreat.MesaShield", finding.ThreatName);
    }

    [Fact]
    public async Task Clean_File_Has_No_Findings()
    {
        var path = WriteFile("notes.txt", Encoding.ASCII.GetBytes("just some fabrication shop notes"));
        var result = await CreateEngine().ScanFileAsync(path, new ScanOptions());
        Assert.True(result.IsClean);
    }

    [Fact]
    public async Task Flags_Double_Extension_Executable()
    {
        var pe = new byte[] { (byte)'M', (byte)'Z' }.Concat(new byte[512]).ToArray();
        var path = WriteFile("invoice.pdf.exe", pe);
        var result = await CreateEngine().ScanFileAsync(path, new ScanOptions());
        Assert.Contains(result.Findings, f => f.ThreatName == "Heur.DoubleExtension" && f.Severity == ThreatSeverity.Malicious);
    }

    [Fact]
    public async Task Flags_Executable_Disguised_As_Image()
    {
        var pe = new byte[] { (byte)'M', (byte)'Z' }.Concat(new byte[512]).ToArray();
        var path = WriteFile("vacation.jpg", pe);
        var result = await CreateEngine().ScanFileAsync(path, new ScanOptions());
        Assert.Contains(result.Findings, f => f.ThreatName == "Heur.DisguisedExecutable");
    }

    [Fact]
    public async Task Flags_Destructive_Script_As_Malicious()
    {
        var script = "vssadmin delete shadows /all /quiet\nwbadmin delete catalog -quiet\n";
        var path = WriteFile("cleanup.bat", Encoding.ASCII.GetBytes(script));
        var result = await CreateEngine().ScanFileAsync(path, new ScanOptions());
        Assert.Contains(result.Findings, f => f.ThreatName == "Heur.DestructiveScript" && f.Severity == ThreatSeverity.Malicious);
    }

    [Fact]
    public async Task Directory_Scan_Reports_Progress_And_Findings()
    {
        WriteFile("a.txt", Encoding.ASCII.GetBytes("clean"));
        WriteFile("b.txt", Encoding.ASCII.GetBytes("also clean"));
        WriteFile("eicar.com", EicarBytes());

        var progressReports = 0;
        var progress = new Progress<ScanProgress>(_ => Interlocked.Increment(ref progressReports));
        var summary = await CreateEngine().ScanAsync(new[] { _dir }, new ScanOptions(), progress);

        Assert.Equal(3, summary.FilesScanned);
        Assert.Single(summary.Findings);
        Assert.False(summary.WasCancelled);
    }

    [Fact]
    public async Task Detects_Eicar_Inside_Zip_Archive()
    {
        var zipPath = Path.Combine(_dir, "bundle.zip");
        using (var archive = System.IO.Compression.ZipFile.Open(zipPath, System.IO.Compression.ZipArchiveMode.Create))
        {
            var entry = archive.CreateEntry("payload/eicar.com");
            using var stream = entry.Open();
            stream.Write(EicarBytes());
        }

        var result = await CreateEngine().ScanFileAsync(zipPath, new ScanOptions());
        Assert.Contains(result.Findings, f => f.ThreatName == "EICAR-Test-File" && f.Detail!.Contains("eicar.com"));
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { /* best effort */ }
    }
}
