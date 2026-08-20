using System.Text;

namespace MesaShield.Core;

/// <summary>
/// Seeds decoy "canary" files in folders ransomware tends to hit first. They're named
/// to sort early alphabetically (many ransomware families encrypt in directory order),
/// look like ordinary documents, and are registered with the BehaviorEngine so any
/// write to them trips an immediate alarm.
/// </summary>
public static class CanaryDeployer
{
    // Leading characters push these to the top of an alphabetical listing.
    private static readonly string[] CanaryNames =
    {
        "!__MesaShield_DoNotDelete.docx",
        "!__accounting_backup.xlsx",
        "aaa_important_records.pdf",
    };

    public static List<string> Deploy(IEnumerable<string> folders, BehaviorEngine engine)
    {
        var created = new List<string>();
        foreach (var folder in folders)
        {
            if (!Directory.Exists(folder)) continue;
            foreach (var canaryName in CanaryNames)
            {
                var path = Path.Combine(folder, canaryName);
                try
                {
                    if (!File.Exists(path))
                        File.WriteAllText(path, CanaryContent(), Encoding.UTF8);
                    // Hide it so the user doesn't stumble on it, but keep it real on disk.
                    try { File.SetAttributes(path, FileAttributes.Hidden); } catch { /* non-fatal */ }
                    engine.RegisterCanary(path);
                    created.Add(path);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    // Can't write here — skip this folder's canary.
                }
            }
        }
        return created;
    }

    private static string CanaryContent() =>
        "This file is a MesaShield ransomware tripwire. Do not modify or delete it. " +
        "If security software reports a change to this file, it is protecting you from ransomware.\n" +
        new string('.', 2048);
}
