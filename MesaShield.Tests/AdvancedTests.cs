using System.Net;
using MesaShield.Core;
using Xunit;

namespace MesaShield.Tests;

public sealed class SemVerTests
{
    [Theory]
    [InlineData("1.2.3", 1, 2, 3)]
    [InlineData("v0.1.0", 0, 1, 0)]
    [InlineData("2.0", 2, 0, 0)]
    [InlineData("1.4.2-beta", 1, 4, 2)]
    public void Parses_Versions(string text, int major, int minor, int patch)
    {
        Assert.True(SemVer.TryParse(text, out var v));
        Assert.Equal(new SemVer(major, minor, patch), v);
    }

    [Fact]
    public void Compares_Correctly()
    {
        Assert.True(new SemVer(1, 0, 0) < new SemVer(1, 0, 1));
        Assert.True(new SemVer(0, 2, 0) > new SemVer(0, 1, 9));
        Assert.True(new SemVer(2, 0, 0) > new SemVer(1, 9, 9));
    }

    [Fact]
    public void Rejects_Garbage() => Assert.False(SemVer.TryParse("not-a-version", out _));
}

public sealed class ScheduleTests
{
    [Fact]
    public void Daily_Schedule_Next_Run_Is_Today_Or_Tomorrow()
    {
        var schedule = new Schedule { Frequency = ScheduleFrequency.Daily, Hour = 2, Minute = 0 };
        var at1am = new DateTimeOffset(2026, 8, 20, 1, 0, 0, TimeSpan.Zero);
        Assert.Equal(2, schedule.NextRun(at1am)!.Value.Hour);
        Assert.Equal(20, schedule.NextRun(at1am)!.Value.Day);

        var at3am = new DateTimeOffset(2026, 8, 20, 3, 0, 0, TimeSpan.Zero);
        Assert.Equal(21, schedule.NextRun(at3am)!.Value.Day); // rolled to tomorrow
    }

    [Fact]
    public void Off_Schedule_Is_Never_Due()
    {
        var schedule = new Schedule { Frequency = ScheduleFrequency.Off };
        Assert.False(JobScheduler.IsDue(schedule, DateTimeOffset.Now));
    }

    [Fact]
    public void Daily_Is_Due_When_Never_Run()
    {
        var schedule = new Schedule { Frequency = ScheduleFrequency.Daily, Hour = 2 };
        var afternoon = new DateTimeOffset(2026, 8, 20, 15, 0, 0, TimeSpan.Zero);
        Assert.True(JobScheduler.IsDue(schedule, afternoon)); // 2am already passed today, never run
    }

    [Fact]
    public void Not_Due_Again_Right_After_Running()
    {
        var schedule = new Schedule { Frequency = ScheduleFrequency.Daily, Hour = 2, LastRunUtc = DateTimeOffset.UtcNow };
        Assert.False(JobScheduler.IsDue(schedule, DateTimeOffset.Now.AddMinutes(1)));
    }
}

public sealed class SettingsTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("mesashield-settings-").FullName;

    [Fact]
    public void Roundtrips_Through_Disk()
    {
        var path = Path.Combine(_dir, "settings.json");
        var settings = AppSettings.Load(path);
        settings.CloudLookupEnabled = true;
        settings.VirusTotalApiKey = "test-key";
        settings.ScanSchedule.Frequency = ScheduleFrequency.Weekly;
        settings.ExcludedExtensions.Add(".iso");
        settings.Save();

        var reloaded = AppSettings.Load(path);
        Assert.True(reloaded.CloudLookupEnabled);
        Assert.Equal("test-key", reloaded.VirusTotalApiKey);
        Assert.Equal(ScheduleFrequency.Weekly, reloaded.ScanSchedule.Frequency);
        Assert.Contains(".iso", reloaded.ToScanOptions().ExcludedExtensions);
    }

    [Fact]
    public void Corrupt_File_Falls_Back_To_Defaults()
    {
        var path = Path.Combine(_dir, "broken.json");
        File.WriteAllText(path, "{ this is not valid json ");
        var settings = AppSettings.Load(path);
        Assert.True(settings.RealTimeProtectionEnabled); // default
    }

    public void Dispose() { try { Directory.Delete(_dir, true); } catch { } }
}

public sealed class BehaviorEngineTests
{
    [Fact]
    public void Canary_Modification_Is_Malicious()
    {
        var engine = new BehaviorEngine();
        engine.RegisterCanary("/data/!__decoy.docx");
        var alert = engine.OnFileChanged("/data/!__decoy.docx", DateTimeOffset.UtcNow, processId: 1234);
        Assert.NotNull(alert);
        Assert.Equal(ThreatSeverity.Malicious, alert!.Severity);
        Assert.Equal("Ransomware.CanaryTriggered", alert.Kind);
        Assert.Equal(1234, alert.SuspectProcessId);
    }

    [Fact]
    public void Ransomware_Extension_Is_Malicious()
    {
        var engine = new BehaviorEngine();
        var alert = engine.OnFileChanged("/docs/report.docx.locked", DateTimeOffset.UtcNow);
        Assert.NotNull(alert);
        Assert.Equal("Ransomware.KnownExtension", alert!.Kind);
    }

    [Fact]
    public void Mass_High_Entropy_Burst_Fires_Encryption_Alert()
    {
        var engine = new BehaviorEngine { BurstThreshold = 40, BurstWindow = TimeSpan.FromSeconds(10) };
        var start = DateTimeOffset.UtcNow;
        BehaviorAlert? alert = null;
        for (var i = 0; i < 45; i++)
            alert ??= engine.OnFileChanged($"/docs/file{i}.dat", start.AddMilliseconds(i * 50), processId: 999, newContentEntropy: 7.9);

        Assert.NotNull(alert);
        Assert.Equal("Ransomware.EncryptionBurst", alert!.Kind);
        Assert.Equal(ThreatSeverity.Malicious, alert.Severity);
    }

    [Fact]
    public void Normal_Activity_Does_Not_Alert()
    {
        var engine = new BehaviorEngine { BurstThreshold = 40 };
        var start = DateTimeOffset.UtcNow;
        for (var i = 0; i < 5; i++)
            Assert.Null(engine.OnFileChanged($"/docs/normal{i}.txt", start.AddSeconds(i)));
    }
}

public sealed class OnlineOnlyFileTests
{
    [Fact]
    public void Normal_File_Is_Not_Online_Only() =>
        Assert.False(ScanEngine.IsOnlineOnly(FileAttributes.Normal | FileAttributes.Archive));

    [Fact]
    public void Offline_Attribute_Is_Online_Only() =>
        Assert.True(ScanEngine.IsOnlineOnly(FileAttributes.Offline));

    [Fact]
    public void RecallOnDataAccess_Attribute_Is_Online_Only() =>
        Assert.True(ScanEngine.IsOnlineOnly((FileAttributes)0x400000));
}

public sealed class ReputationClientTests
{
    private sealed class StubHandler : HttpMessageHandler
    {
        private readonly HttpStatusCode _code;
        private readonly string _body;
        public StubHandler(HttpStatusCode code, string body) { _code = code; _body = body; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) =>
            Task.FromResult(new HttpResponseMessage(_code) { Content = new StringContent(_body) });
    }

    private static string CachePath() => Path.Combine(Path.GetTempPath(), $"vt-cache-{Guid.NewGuid():N}.json");

    [Fact]
    public async Task Disabled_Without_Key()
    {
        var client = new ReputationClient(new HttpClient(new StubHandler(HttpStatusCode.OK, "{}")), null, 3, CachePath());
        Assert.False(client.IsEnabled);
        var result = await client.LookupAsync(new string('a', 64));
        Assert.Equal(ReputationVerdict.Unknown, result.Verdict);
    }

    [Fact]
    public async Task Flags_Malicious_Above_Threshold()
    {
        const string body = """
        {"data":{"attributes":{"last_analysis_stats":{"malicious":40,"suspicious":2,"harmless":10,"undetected":20},
        "popular_threat_classification":{"suggested_threat_label":"trojan.generic"}}}}
        """;
        var client = new ReputationClient(new HttpClient(new StubHandler(HttpStatusCode.OK, body)), "key", 3, CachePath());
        var result = await client.LookupAsync(new string('b', 64));
        Assert.Equal(ReputationVerdict.Malicious, result.Verdict);
        Assert.Equal("trojan.generic", result.Label);
        Assert.Equal(42, result.Positives);
    }

    [Fact]
    public async Task Clean_When_No_Engine_Flags()
    {
        const string body = """
        {"data":{"attributes":{"last_analysis_stats":{"malicious":0,"suspicious":0,"harmless":60,"undetected":10}}}}
        """;
        var client = new ReputationClient(new HttpClient(new StubHandler(HttpStatusCode.OK, body)), "key", 3, CachePath());
        var result = await client.LookupAsync(new string('c', 64));
        Assert.Equal(ReputationVerdict.Clean, result.Verdict);
    }

    [Fact]
    public async Task NotFound_Is_Unknown_Not_Clean()
    {
        var client = new ReputationClient(new HttpClient(new StubHandler(HttpStatusCode.NotFound, "")), "key", 3, CachePath());
        var result = await client.LookupAsync(new string('d', 64));
        Assert.Equal(ReputationVerdict.Unknown, result.Verdict);
    }
}

public sealed class UpdateCheckerTests
{
    private sealed class JsonHandler : HttpMessageHandler
    {
        private readonly string _body;
        public JsonHandler(string body) => _body = body;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(_body) });
    }

    [Fact]
    public async Task Detects_Newer_Version_From_Manifest()
    {
        const string manifest = """
        {"version":"0.2.0","notes":"New stuff","downloadUrl":"https://example.com/app.zip"}
        """;
        var checker = new UpdateChecker(new HttpClient(new JsonHandler(manifest)));
        var result = await checker.CheckAsync("https://example.com/manifest.json", new SemVer(0, 1, 0));
        Assert.True(result.UpdateAvailable);
        Assert.Equal("0.2.0", result.Release!.Version);
    }

    [Fact]
    public async Task No_Update_When_Current_Is_Latest()
    {
        const string manifest = """{"version":"0.1.0","downloadUrl":"https://example.com/app.zip"}""";
        var checker = new UpdateChecker(new HttpClient(new JsonHandler(manifest)));
        var result = await checker.CheckAsync("https://example.com/manifest.json", new SemVer(0, 1, 0));
        Assert.False(result.UpdateAvailable);
    }
}
