using System.Text.Json;

namespace MesaShield.Core.Incidents;

/// <summary>
/// Turns a raw detection into an incident *story*. Given the triggering event and the machine's
/// recent activity log, it correlates everything that happened around it — the file arriving, a
/// process launching, a network connection, a behavior alert — into an ordered, plain-English
/// timeline with a summary, outcome, and recommendation. This is the difference between
/// "quarantined a file" and "here is exactly what tried to happen and what we did about it."
/// </summary>
public static class IncidentBuilder
{
    private static readonly HashSet<string> SecurityKinds = new(StringComparer.OrdinalIgnoreCase)
    { "quarantine", "blocked", "detection", "anomaly", "behavior", "egress", "tamper", "restore" };

    /// <summary>Build an incident from a trigger event and the surrounding activity log.</summary>
    public static Incident Build(
        ShieldEventLog.ShieldEvent trigger,
        IReadOnlyList<ShieldEventLog.ShieldEvent> recentEvents,
        TimeSpan window)
    {
        var start = trigger.Timestamp - window;
        var end = trigger.Timestamp + window;
        var fileName = FileNameOf(trigger.FilePath);

        // Relevant = security events in the window, or anything mentioning the same file/threat.
        var related = recentEvents
            .Where(e => e.Timestamp >= start && e.Timestamp <= end)
            .Where(e =>
                SecurityKinds.Contains(e.Kind) ||
                (fileName is not null && (e.FilePath?.EndsWith(fileName, StringComparison.OrdinalIgnoreCase) == true ||
                                          e.Message.Contains(fileName, StringComparison.OrdinalIgnoreCase))))
            .OrderBy(e => e.Timestamp)
            .ToList();
        if (!related.Any(e => e.Timestamp == trigger.Timestamp && e.Message == trigger.Message))
            related.Add(trigger);
        related = related.OrderBy(e => e.Timestamp).ToList();

        var timeline = related.Select(e => new TimelineEntry(e.Timestamp, e.Kind, e.Message, e.FilePath)).ToList();

        var affectedFiles = related.Select(e => e.FilePath).Where(f => f is not null).Distinct().Cast<string>().ToList();
        var destinations = related
            .Where(e => e.Kind.Equals("egress", StringComparison.OrdinalIgnoreCase))
            .Select(e => ExtractDestination(e.Message))
            .Where(d => d is not null).Distinct().Cast<string>().ToList();

        var severity = trigger.Kind is "quarantine" or "blocked" or "anomaly" or "tamper"
            ? ThreatSeverity.Malicious : ThreatSeverity.Suspicious;

        var title = trigger.ThreatName is not null
            ? $"{trigger.ThreatName}" + (fileName is not null ? $" in {fileName}" : "")
            : (fileName is not null ? $"Suspicious activity involving {fileName}" : "Suspicious activity");

        var outcome = trigger.Kind switch
        {
            "quarantine" => "The file was encrypted into quarantine and can no longer run.",
            "blocked" => "The action was blocked before it could complete.",
            "egress" => "The outbound connection was handled by egress control.",
            "tamper" => "Protection was automatically restored.",
            _ => "The activity was flagged for your review.",
        };

        var recommendation = severity == ThreatSeverity.Malicious
            ? "No action needed — MesaShield contained it. Review the timeline; if this program is one you trust, you can restore it from Quarantine."
            : "Review the timeline. If this was expected activity, no action is needed; if not, run a full scan and consider blocking the program in the Firewall/Traffic view.";

        var summary = BuildSummary(trigger, fileName, timeline.Count, destinations);

        return new Incident
        {
            Id = Guid.NewGuid().ToString("N"),
            Title = title,
            Severity = severity,
            OccurredUtc = trigger.Timestamp,
            PrimaryFile = trigger.FilePath,
            ThreatName = trigger.ThreatName,
            Summary = summary,
            Outcome = outcome,
            Recommendation = recommendation,
            Timeline = timeline,
            AffectedFiles = affectedFiles,
            NetworkDestinations = destinations,
        };
    }

    private static string BuildSummary(ShieldEventLog.ShieldEvent trigger, string? fileName, int steps, List<string> destinations)
    {
        var what = trigger.ThreatName is not null ? $"“{trigger.ThreatName}”" : "suspicious activity";
        var where = fileName is not null ? $" involving {fileName}" : "";
        var net = destinations.Count > 0 ? $" It attempted to reach {destinations.Count} external destination(s)." : "";
        return $"MesaShield detected {what}{where} at {trigger.Timestamp.ToLocalTime():t}. " +
               $"The reconstructed timeline covers {steps} related event(s).{net}";
    }

    /// <summary>Last path segment, robust to both / and \ separators (events may carry Windows paths).</summary>
    private static string? FileNameOf(string? path)
    {
        if (string.IsNullOrEmpty(path)) return null;
        var idx = path.LastIndexOfAny(new[] { '\\', '/' });
        return idx >= 0 && idx < path.Length - 1 ? path[(idx + 1)..] : path;
    }

    private static string? ExtractDestination(string message)
    {
        // Egress messages look like "... <proc> → <ip>:<port> ..."; pull the address if present.
        var arrow = message.IndexOf('→');
        if (arrow < 0) return null;
        var rest = message[(arrow + 1)..].Trim();
        var space = rest.IndexOf(' ');
        return space > 0 ? rest[..space] : rest;
    }
}

/// <summary>Persists incidents as JSON files so they survive restarts and can be reviewed later.</summary>
public sealed class IncidentStore
{
    private readonly string _dir;
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() },
    };

    public IncidentStore(string directory) { _dir = directory; Directory.CreateDirectory(directory); }

    public void Save(Incident incident)
    {
        var path = Path.Combine(_dir, $"{incident.OccurredUtc.UtcDateTime:yyyyMMdd-HHmmss}-{incident.Id[..8]}.json");
        File.WriteAllText(path, JsonSerializer.Serialize(incident, JsonOptions));
    }

    public List<Incident> LoadRecent(int max = 100)
    {
        var list = new List<Incident>();
        if (!Directory.Exists(_dir)) return list;
        foreach (var file in Directory.EnumerateFiles(_dir, "*.json").OrderByDescending(f => f).Take(max))
        {
            try { var i = JsonSerializer.Deserialize<Incident>(File.ReadAllText(file), JsonOptions); if (i is not null) list.Add(i); }
            catch (Exception ex) when (ex is JsonException or IOException) { }
        }
        return list.OrderByDescending(i => i.OccurredUtc).ToList();
    }
}
