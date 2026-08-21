using System.Diagnostics;
using System.Reflection;
using MesaShield.Core;
using MesaShield.Windows;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace MesaShield.Service;

/// <summary>
/// The service's lifetime wrapper around <see cref="ShieldEngineHost"/>. It initializes the engine
/// once at startup, then heartbeats the machine status on a short cadence so the desktop viewer
/// always sees fresh state. On shutdown it disposes the engine cleanly (saving learners/models).
/// </summary>
public sealed class ShieldWorker : BackgroundService
{
    public const string ServiceName = "MesaShield";

    /// <summary>Machine-wide data root so the LocalSystem service and any signed-in user's viewer
    /// share the same signatures, quarantine, incidents, settings, and status.</summary>
    public static string DataDirectory { get; } = System.IO.Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "MesaShield");

    private readonly ILogger<ShieldWorker> _log;
    private ShieldEngineHost? _engine;

    public ShieldWorker(ILogger<ShieldWorker> log) => _log = log;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            System.IO.Directory.CreateDirectory(DataDirectory);
            var settings = AppSettings.Load(System.IO.Path.Combine(DataDirectory, "settings.json"));

            // Apply an admin-supplied managed config if present (fleet folder, update source, toggles).
            foreach (var configPath in new[]
                     {
                         System.IO.Path.Combine(AppContext.BaseDirectory, DeployConfig.FileName),
                         System.IO.Path.Combine(DataDirectory, DeployConfig.FileName),
                     })
            {
                try { DeployConfig.Load(configPath)?.ApplyTo(settings); } catch { }
            }

            var version = ResolveVersion();
            _engine = new ShieldEngineHost(DataDirectory, version, settings);

            // Surface a few notable engine events into the Windows Event Log for operators.
            _engine.IncidentRecorded += i => _log.LogWarning("MesaShield incident: {Title} ({Severity})", i.Title, i.Severity);
            _engine.TamperHealed += name => _log.LogWarning("MesaShield self-defense restarted: {Module}", name);
            _engine.UpdateReadyToInstall += (dest, ver) => OnUpdateReady(dest, ver);

            await _engine.InitializeAsync();
            _log.LogInformation("MesaShield engine {Version} running as a service (data: {Dir}).", version, DataDirectory);

            // Heartbeat: refresh status frequently so the viewer sees live state.
            while (!stoppingToken.IsCancellationRequested)
            {
                try { _engine.Fleet.Report(); } catch { /* best-effort */ }
                try { await Task.Delay(TimeSpan.FromSeconds(10), stoppingToken); }
                catch (OperationCanceledException) { break; }
            }
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "MesaShield service failed to start the engine.");
            throw;   // let the service host report failure so Windows recovery can restart us
        }
    }

    /// <summary>A verified newer installer is ready. Launch it silently; it stops this service,
    /// swaps the files, and restarts the service. We do not tear ourselves down here — the
    /// installer manages the service lifecycle.</summary>
    private void OnUpdateReady(string installerPath, string version)
    {
        try
        {
            _log.LogInformation("MesaShield update v{Version} ready — launching silent installer.", version);
            Process.Start(new ProcessStartInfo
            {
                FileName = installerPath,
                Arguments = "--silent --update-service",
                UseShellExecute = false,
                CreateNoWindow = true,
            });
        }
        catch (Exception ex) { _log.LogError(ex, "Failed to launch MesaShield update installer."); }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        try { _engine?.Dispose(); } catch { /* best-effort */ }
        _log.LogInformation("MesaShield service stopped.");
        await base.StopAsync(cancellationToken);
    }

    private static SemVer ResolveVersion()
    {
        var v = Assembly.GetExecutingAssembly().GetName().Version;
        return v is null ? new SemVer(0, 19, 0) : new SemVer(v.Major, v.Minor, v.Build);
    }
}
