using System.Management;
using MesaShield.Core;

namespace MesaShield.Windows;

/// <summary>
/// Detects USB / removable drive insertion via WMI volume-change events and hands
/// the new drive to real-time protection (auto-watch) and optionally a full scan.
/// </summary>
public sealed class UsbWatcher : IDisposable
{
    private readonly ShieldEventLog _log;
    private ManagementEventWatcher? _watcher;

    /// <summary>Raised with the drive root (e.g. "E:\") when a removable drive appears.</summary>
    public event Action<string>? DriveInserted;

    /// <summary>Raised with the drive root when a removable drive is removed.</summary>
    public event Action<string>? DriveRemoved;

    public UsbWatcher(ShieldEventLog log) => _log = log;

    public void Start()
    {
        if (!OperatingSystem.IsWindows()) return;

        // EventType 2 = device arrival, 3 = device removal.
        var query = new WqlEventQuery("SELECT * FROM Win32_VolumeChangeEvent WHERE EventType = 2 OR EventType = 3");
        _watcher = new ManagementEventWatcher(query);
        _watcher.EventArrived += OnVolumeChange;
        _watcher.Start();
    }

    private void OnVolumeChange(object sender, EventArrivedEventArgs e)
    {
        try
        {
            var driveName = e.NewEvent.Properties["DriveName"]?.Value?.ToString();
            var eventType = Convert.ToInt32(e.NewEvent.Properties["EventType"].Value);
            if (string.IsNullOrEmpty(driveName)) return;
            var root = driveName + "\\";

            if (eventType == 2)
            {
                _ = _log.LogAsync("usb", $"Removable drive inserted: {root}");
                DriveInserted?.Invoke(root);
            }
            else if (eventType == 3)
            {
                _ = _log.LogAsync("usb", $"Removable drive removed: {root}");
                DriveRemoved?.Invoke(root);
            }
        }
        catch (Exception ex)
        {
            _ = _log.LogAsync("error", $"USB watcher error: {ex.Message}");
        }
    }

    public void Dispose()
    {
        if (_watcher is null) return;
        _watcher.EventArrived -= OnVolumeChange;
        try { _watcher.Stop(); } catch (ManagementException) { /* already stopped */ }
        _watcher.Dispose();
    }
}
