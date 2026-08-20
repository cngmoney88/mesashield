using System.Text.Json;
using System.Text.Json.Serialization;

namespace MesaShield.Core;

/// <summary>How often a recurring job runs.</summary>
public enum ScheduleFrequency { Off, Hourly, Daily, Weekly }

/// <summary>A recurring job definition (used for scans and signature updates).</summary>
public sealed class Schedule
{
    public ScheduleFrequency Frequency { get; set; } = ScheduleFrequency.Daily;
    /// <summary>Hour of day (0-23) for daily/weekly runs, local time.</summary>
    public int Hour { get; set; } = 2;
    public int Minute { get; set; }
    /// <summary>Day of week for weekly runs.</summary>
    public DayOfWeek DayOfWeek { get; set; } = DayOfWeek.Sunday;
    public DateTimeOffset? LastRunUtc { get; set; }

    /// <summary>Next run time at or after <paramref name="fromLocal"/>, or null if Off.</summary>
    public DateTimeOffset? NextRun(DateTimeOffset fromLocal)
    {
        switch (Frequency)
        {
            case ScheduleFrequency.Off:
                return null;

            case ScheduleFrequency.Hourly:
            {
                var next = new DateTimeOffset(fromLocal.Year, fromLocal.Month, fromLocal.Day,
                    fromLocal.Hour, Minute, 0, fromLocal.Offset);
                if (next <= fromLocal) next = next.AddHours(1);
                return next;
            }

            case ScheduleFrequency.Daily:
            {
                var next = new DateTimeOffset(fromLocal.Year, fromLocal.Month, fromLocal.Day,
                    Hour, Minute, 0, fromLocal.Offset);
                if (next <= fromLocal) next = next.AddDays(1);
                return next;
            }

            case ScheduleFrequency.Weekly:
            {
                var next = new DateTimeOffset(fromLocal.Year, fromLocal.Month, fromLocal.Day,
                    Hour, Minute, 0, fromLocal.Offset);
                var daysUntil = ((int)DayOfWeek - (int)fromLocal.DayOfWeek + 7) % 7;
                next = next.AddDays(daysUntil);
                if (next <= fromLocal) next = next.AddDays(7);
                return next;
            }

            default:
                return null;
        }
    }
}

/// <summary>Which target set a scheduled scan covers.</summary>
public enum ScheduledScanScope { QuickScan, FullScan }

/// <summary>All persisted user configuration. Serialized to settings.json in the data dir.</summary>
public sealed class AppSettings
{
    /// <summary>False until the first launch has completed its one-time setup (initial signature download).</summary>
    public bool FirstRunCompleted { get; set; }

    // Protection toggles
    public bool RealTimeProtectionEnabled { get; set; } = true;
    public bool ProcessMonitoringEnabled { get; set; } = true;
    public bool BehaviorGuardEnabled { get; set; } = true;
    public bool AmsiScriptScanningEnabled { get; set; } = true;
    public bool UsbAutoScanEnabled { get; set; } = true;

    /// <summary>On-device anomaly learning (learns this machine's normal, flags outliers).</summary>
    public bool AdaptiveLearningEnabled { get; set; } = true;

    /// <summary>Egress / data-loss-prevention mode: Off, Observe (alert only), or Enforce (block).</summary>
    public Net.EgressMode EgressMode { get; set; } = Net.EgressMode.Observe;

    /// <summary>Offline ML malware classifier layer during scans.</summary>
    public bool MlClassifierEnabled { get; set; } = true;

    /// <summary>Deep real-time telemetry via ETW (needs administrator). Learns process + network normal.</summary>
    public bool EtwMonitoringEnabled { get; set; } = true;

    // Scheduling
    public Schedule ScanSchedule { get; set; } = new() { Frequency = ScheduleFrequency.Daily, Hour = 2 };
    public ScheduledScanScope ScheduledScanScope { get; set; } = ScheduledScanScope.QuickScan;
    public Schedule SignatureUpdateSchedule { get; set; } = new() { Frequency = ScheduleFrequency.Daily, Hour = 3 };

    // Privacy
    /// <summary>Network policy: Standard, Strict (no fingerprints leave), or Offline (no internet at all).</summary>
    public Privacy.PrivacyMode PrivacyMode { get; set; } = Privacy.PrivacyMode.Standard;
    /// <summary>Optional local folder to pull signature updates from instead of the internet (offline fleets).</summary>
    public string LocalSignatureMirror { get; set; } = "";
    /// <summary>Auto-delete activity logs older than this many days. 0 = keep forever.</summary>
    public int LogRetentionDays { get; set; } = 90;

    // Cloud reputation
    public bool CloudLookupEnabled { get; set; }
    /// <summary>VirusTotal API key. Optional — cloud lookups are disabled without it.</summary>
    public string? VirusTotalApiKey { get; set; }
    /// <summary>Minimum number of VT engines flagging a file before we treat cloud verdict as malicious.</summary>
    public int CloudMaliciousThreshold { get; set; } = 3;

    // Auto-update (of the app itself)
    public bool AutoUpdateEnabled { get; set; } = true;
    /// <summary>Install found updates automatically in the background, with no prompt or click.</summary>
    public bool AutoInstallUpdates { get; set; } = true;
    /// <summary>URL of a JSON release manifest, or a GitHub "owner/repo" for the Releases API.
    /// Pre-configured to the MesaShield repo so machines self-update out of the box.</summary>
    public string UpdateChannel { get; set; } = "cngmoney88/mesashield";
    /// <summary>Check for app updates every few hours so machines stay current without anyone looking.</summary>
    public Schedule UpdateCheckSchedule { get; set; } = new() { Frequency = ScheduleFrequency.Hourly, Minute = 15 };

    // Fleet dashboard
    public bool FleetReportingEnabled { get; set; } = true;
    /// <summary>Shared folder where machines write status (e.g. \\SERVER\MesaShield\status). Blank = local only.</summary>
    public string FleetSharedFolder { get; set; } = "";

    // Startup / UX
    public bool RunAtStartup { get; set; } = true;
    public bool StartMinimizedToTray { get; set; } = true;
    public bool ShowNotifications { get; set; } = true;

    // Scan behavior
    public List<string> ExcludedPaths { get; set; } = new();
    public List<string> ExcludedExtensions { get; set; } = new();

    [JsonIgnore] public string? SourcePath { get; private set; }

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
    };

    public static AppSettings Load(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                var settings = JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(path), JsonOptions);
                if (settings is not null) { settings.SourcePath = path; return settings; }
            }
        }
        catch (Exception ex) when (ex is JsonException or IOException) { /* fall through to defaults */ }

        var fresh = new AppSettings { SourcePath = path };
        fresh.Save();
        return fresh;
    }

    public void Save()
    {
        if (SourcePath is null) return;
        Directory.CreateDirectory(Path.GetDirectoryName(SourcePath)!);
        var temp = SourcePath + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(this, JsonOptions));
        File.Move(temp, SourcePath, overwrite: true);
    }

    /// <summary>Build a <see cref="ScanOptions"/> honoring the user's exclusions.</summary>
    public ScanOptions ToScanOptions()
    {
        var options = new ScanOptions();
        options.ExcludedPaths.AddRange(ExcludedPaths);
        foreach (var ext in ExcludedExtensions)
            options.ExcludedExtensions.Add(ext.StartsWith('.') ? ext : "." + ext);
        return options;
    }
}
