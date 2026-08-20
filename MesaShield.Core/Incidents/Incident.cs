using System.Text;

namespace MesaShield.Core.Incidents;

/// <summary>One step in an incident's reconstructed story.</summary>
public sealed record TimelineEntry(DateTimeOffset At, string Kind, string What, string? File = null);

/// <summary>A reconstructed security incident — the story around a detection, not just the detection.</summary>
public sealed record Incident
{
    public required string Id { get; init; }
    public required string Title { get; init; }
    public required ThreatSeverity Severity { get; init; }
    public required DateTimeOffset OccurredUtc { get; init; }
    public string? PrimaryFile { get; init; }
    public string? ThreatName { get; init; }
    public required string Summary { get; init; }
    public string Outcome { get; init; } = "";
    public string Recommendation { get; init; } = "";
    public IReadOnlyList<TimelineEntry> Timeline { get; init; } = Array.Empty<TimelineEntry>();
    public IReadOnlyList<string> AffectedFiles { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> NetworkDestinations { get; init; } = Array.Empty<string>();

    /// <summary>A shareable plain-text report of the incident.</summary>
    public string ToReport(string machineName)
    {
        var sb = new StringBuilder();
        sb.AppendLine("MESASHIELD INCIDENT REPORT");
        sb.AppendLine("==========================");
        sb.AppendLine($"Machine:    {machineName}");
        sb.AppendLine($"Incident:   {Title}");
        sb.AppendLine($"Severity:   {Severity}");
        sb.AppendLine($"When:       {OccurredUtc.ToLocalTime():f}");
        if (ThreatName is not null) sb.AppendLine($"Threat:     {ThreatName}");
        if (PrimaryFile is not null) sb.AppendLine($"File:       {PrimaryFile}");
        sb.AppendLine();
        sb.AppendLine("SUMMARY");
        sb.AppendLine(Summary);
        sb.AppendLine();
        sb.AppendLine("WHAT HAPPENED (timeline)");
        foreach (var t in Timeline)
            sb.AppendLine($"  {t.At.ToLocalTime():HH:mm:ss}  [{t.Kind}]  {t.What}");
        if (NetworkDestinations.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("NETWORK DESTINATIONS");
            foreach (var d in NetworkDestinations) sb.AppendLine($"  {d}");
        }
        if (AffectedFiles.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("FILES INVOLVED");
            foreach (var f in AffectedFiles) sb.AppendLine($"  {f}");
        }
        sb.AppendLine();
        sb.AppendLine($"OUTCOME: {Outcome}");
        sb.AppendLine($"RECOMMENDED: {Recommendation}");
        return sb.ToString();
    }
}
