using System.Text.Json;

namespace MesaShield.Core;

/// <summary>
/// Optional deployment configuration an administrator ships with the installer so a machine
/// comes up already pointed at the right shared folder and update source — no per-machine
/// clicking. Placed as "MesaShield.deploy.json" next to the installer (or in
/// %ProgramData%\MesaShield). Only the fields present are applied; nulls leave defaults alone.
/// </summary>
public sealed class DeployConfig
{
    public string? FleetSharedFolder { get; set; }
    public string? UpdateChannel { get; set; }
    public string? VirusTotalApiKey { get; set; }
    public bool? FleetReportingEnabled { get; set; }
    public bool? AdaptiveLearningEnabled { get; set; }
    public bool? MlClassifierEnabled { get; set; }
    public bool? CloudLookupEnabled { get; set; }
    public bool? RunAtStartup { get; set; }
    public bool? AutoUpdateEnabled { get; set; }

    public const string FileName = "MesaShield.deploy.json";

    public static DeployConfig? Load(string path)
    {
        try
        {
            if (!File.Exists(path)) return null;
            return JsonSerializer.Deserialize<DeployConfig>(File.ReadAllText(path),
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
        }
        catch (Exception ex) when (ex is JsonException or IOException)
        {
            return null;
        }
    }

    /// <summary>Apply set fields onto settings. Returns true if anything changed.</summary>
    public bool ApplyTo(AppSettings settings)
    {
        var changed = false;
        void Set<T>(T? value, Action<T> apply) where T : struct
        { if (value.HasValue) { apply(value.Value); changed = true; } }

        if (FleetSharedFolder is not null) { settings.FleetSharedFolder = FleetSharedFolder; changed = true; }
        if (UpdateChannel is not null) { settings.UpdateChannel = UpdateChannel; changed = true; }
        if (VirusTotalApiKey is not null) { settings.VirusTotalApiKey = VirusTotalApiKey; changed = true; }
        Set(FleetReportingEnabled, v => settings.FleetReportingEnabled = v);
        Set(AdaptiveLearningEnabled, v => settings.AdaptiveLearningEnabled = v);
        Set(MlClassifierEnabled, v => settings.MlClassifierEnabled = v);
        Set(CloudLookupEnabled, v => settings.CloudLookupEnabled = v);
        Set(RunAtStartup, v => settings.RunAtStartup = v);
        Set(AutoUpdateEnabled, v => settings.AutoUpdateEnabled = v);

        if (changed) settings.Save();
        return changed;
    }
}
