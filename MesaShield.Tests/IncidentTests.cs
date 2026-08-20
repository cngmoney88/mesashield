using MesaShield.Core;
using MesaShield.Core.Incidents;
using Xunit;

namespace MesaShield.Tests;

public sealed class IncidentTests
{
    private static ShieldEventLog.ShieldEvent E(int secondsAgo, string kind, string msg, string? file = null, string? threat = null) =>
        new(DateTimeOffset.UtcNow.AddSeconds(-secondsAgo), kind, msg, file, threat);

    [Fact]
    public void Reconstructs_A_Story_Around_A_Detection()
    {
        var events = new List<ShieldEventLog.ShieldEvent>
        {
            E(30, "realtime", "New file appeared in Downloads: invoice.pdf.exe", @"C:\Users\x\Downloads\invoice.pdf.exe"),
            E(25, "detection", "Heuristic: executable disguised as a document", @"C:\Users\x\Downloads\invoice.pdf.exe", "Heur.DoubleExtension"),
            E(20, "egress", "BLOCK: invoice → 45.83.12.9:4444 unfamiliar destination"),
            E(18, "quarantine", "Quarantined Heur.DoubleExtension", @"C:\Users\x\Downloads\invoice.pdf.exe", "Heur.DoubleExtension"),
            E(600, "app", "MesaShield started"),  // outside window / not relevant
        };
        var trigger = events[3]; // the quarantine

        var incident = IncidentBuilder.Build(trigger, events, TimeSpan.FromMinutes(5));

        Assert.Equal(ThreatSeverity.Malicious, incident.Severity);
        Assert.Contains("invoice.pdf.exe", incident.Title);
        Assert.True(incident.Timeline.Count >= 3);                 // the related security events
        Assert.DoesNotContain(incident.Timeline, t => t.What == "MesaShield started"); // irrelevant/old excluded
        Assert.Contains(incident.NetworkDestinations, d => d.Contains("45.83.12.9"));
        Assert.Contains("quarantine", incident.Outcome, System.StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Report_Is_Readable_And_Complete()
    {
        var events = new List<ShieldEventLog.ShieldEvent> { E(5, "quarantine", "Quarantined X", @"C:\a\b.exe", "Trojan.X") };
        var incident = IncidentBuilder.Build(events[0], events, TimeSpan.FromMinutes(5));
        var report = incident.ToReport("SHOP-1");
        Assert.Contains("MESASHIELD INCIDENT REPORT", report);
        Assert.Contains("SHOP-1", report);
        Assert.Contains("Trojan.X", report);
        Assert.Contains("RECOMMENDED", report);
    }

    [Fact]
    public void Store_Roundtrips()
    {
        var dir = Directory.CreateTempSubdirectory("mesashield-incidents-").FullName;
        try
        {
            var store = new IncidentStore(dir);
            var events = new List<ShieldEventLog.ShieldEvent> { E(5, "blocked", "Blocked Y", @"C:\a\y.exe", "Mal.Y") };
            store.Save(IncidentBuilder.Build(events[0], events, TimeSpan.FromMinutes(5)));
            var loaded = store.LoadRecent();
            Assert.Single(loaded);
            Assert.Equal("Mal.Y in y.exe", loaded[0].Title);
        }
        finally { Directory.Delete(dir, true); }
    }
}
