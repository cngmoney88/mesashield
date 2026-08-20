namespace MesaShield.Windows;

/// <summary>
/// Removes the "downloaded from the internet" tag (the Zone.Identifier alternate data stream)
/// that Windows attaches to files fetched over the network. That tag is what triggers the
/// SmartScreen "Windows protected your PC" prompt. We strip it ONLY after the download has been
/// verified against its published SHA-256, so a fully-automatic update can install without a
/// prompt — without weakening the integrity check.
/// </summary>
public static class MarkOfTheWeb
{
    public static void Remove(string filePath)
    {
        if (!OperatingSystem.IsWindows()) return;
        try
        {
            // The zone info lives in an NTFS alternate data stream named "Zone.Identifier".
            var adsPath = filePath + ":Zone.Identifier";
            if (File.Exists(adsPath)) File.Delete(adsPath);
        }
        catch (Exception) { /* best-effort; if it fails the user just sees the normal prompt */ }
    }
}
