using System.Text.Json;

namespace MesaShield.Core;

/// <summary>Actions the fleet dashboard can push to machines.</summary>
public enum FleetCommandType
{
    QuickScan,
    FullScan,
    UpdateSignatures,
    CheckAppUpdate,
    SetPrivacyMode,     // Arg = "Standard" | "Strict" | "Offline"
    SetEgressMode,      // Arg = "Off" | "Observe" | "Enforce"
    Ping,
}

/// <summary>A command issued to one machine ("MACHINE-NAME") or the whole fleet ("*").</summary>
public sealed record FleetCommand
{
    public required string Id { get; init; }
    public required string Target { get; init; }         // machine name, or "*" for all
    public required FleetCommandType Type { get; init; }
    public string? Arg { get; init; }
    public DateTimeOffset IssuedUtc { get; init; } = DateTimeOffset.UtcNow;
    public string IssuedBy { get; init; } = Environment.MachineName;

    public bool AppliesTo(string machineName) =>
        Target == "*" || string.Equals(Target, machineName, StringComparison.OrdinalIgnoreCase);
}

/// <summary>
/// The fleet control channel, built on the same shared folder as status reporting — no server
/// software, all on the LAN. The dashboard drops command files into a "commands" subfolder;
/// each machine reads the ones addressed to it, runs them, and writes an ack so a fleet-wide
/// command is only run once per machine. Everything is plain JSON files.
/// </summary>
public static class FleetCommander
{
    private static string CommandsDir(string shared) => Path.Combine(shared, "commands");
    private static string AcksDir(string shared) => Path.Combine(shared, "acks");
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    /// <summary>Dashboard side: issue a command to a machine or the whole fleet. Returns the command id.</summary>
    public static string Issue(string sharedFolder, FleetCommandType type, string target, string? arg = null)
    {
        var command = new FleetCommand
        {
            Id = Guid.NewGuid().ToString("N"),
            Target = target,
            Type = type,
            Arg = arg,
        };
        var dir = CommandsDir(sharedFolder);
        Directory.CreateDirectory(dir);
        var tmp = Path.Combine(dir, command.Id + ".json.tmp");
        File.WriteAllText(tmp, JsonSerializer.Serialize(command, JsonOptions));
        File.Move(tmp, Path.Combine(dir, command.Id + ".json"), overwrite: true);
        return command.Id;
    }

    /// <summary>Machine side: the commands addressed to this machine that it hasn't run yet.</summary>
    public static List<FleetCommand> Pending(string sharedFolder, string machineName)
    {
        var pending = new List<FleetCommand>();
        var dir = CommandsDir(sharedFolder);
        if (!Directory.Exists(dir)) return pending;

        foreach (var file in Directory.EnumerateFiles(dir, "*.json"))
        {
            try
            {
                var command = JsonSerializer.Deserialize<FleetCommand>(File.ReadAllText(file));
                if (command is null || !command.AppliesTo(machineName)) continue;
                if (!IsAcked(sharedFolder, command.Id, machineName)) pending.Add(command);
            }
            catch (Exception ex) when (ex is JsonException or IOException) { }
        }
        return pending.OrderBy(c => c.IssuedUtc).ToList();
    }

    /// <summary>Machine side: record that this machine ran a command (so "*" commands run once each).</summary>
    public static void Ack(string sharedFolder, string commandId, string machineName)
    {
        var dir = AcksDir(sharedFolder);
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, $"{commandId}__{FleetReporter.StatusFileName(machineName)}");
        try { File.WriteAllText(path, DateTimeOffset.UtcNow.ToString("o")); }
        catch (IOException) { }
    }

    public static bool IsAcked(string sharedFolder, string commandId, string machineName) =>
        File.Exists(Path.Combine(AcksDir(sharedFolder), $"{commandId}__{FleetReporter.StatusFileName(machineName)}"));

    /// <summary>Housekeeping: drop command and ack files older than the retention window.</summary>
    public static void Cleanup(string sharedFolder, TimeSpan olderThan)
    {
        var cutoff = DateTimeOffset.UtcNow - olderThan;
        foreach (var dir in new[] { CommandsDir(sharedFolder), AcksDir(sharedFolder) })
        {
            if (!Directory.Exists(dir)) continue;
            foreach (var file in Directory.EnumerateFiles(dir))
            {
                try { if (new DateTimeOffset(File.GetLastWriteTimeUtc(file), TimeSpan.Zero) < cutoff) File.Delete(file); }
                catch (IOException) { }
            }
        }
    }
}
