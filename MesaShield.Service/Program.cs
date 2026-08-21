using MesaShield.Service;
using MesaShield.Windows;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

// Command-line management (run as Administrator):
//   MesaShield-Service.exe install     register + start the always-on service
//   MesaShield-Service.exe uninstall   stop + remove it
//   MesaShield-Service.exe start|stop  control it
// With no verb, the process runs as the service itself (how Windows launches it).
if (args.Length > 0)
{
    var verb = args[0].Trim().ToLowerInvariant();
    var exe = Environment.ProcessPath ?? System.Reflection.Assembly.GetExecutingAssembly().Location;
    switch (verb)
    {
        case "install":
            Console.WriteLine(ServiceControl.Install(exe)
                ? "MesaShield service installed and started."
                : "Failed to install the MesaShield service (run as Administrator).");
            return;
        case "uninstall":
            Console.WriteLine(ServiceControl.Uninstall() ? "MesaShield service removed." : "Failed to remove the service.");
            return;
        case "start":
            Console.WriteLine(ServiceControl.Start() ? "Started." : "Failed to start.");
            return;
        case "stop":
            Console.WriteLine(ServiceControl.Stop() ? "Stopped." : "Failed to stop.");
            return;
    }
    // Unknown verb (e.g. "--silent --update-service") falls through to running the service.
}

// MesaShield always-on protection service.
//
// Runs the exact same ShieldEngineHost the desktop app uses, but headless and under LocalSystem,
// so protection is active before anyone logs in and keeps running with no window open. Windows
// restarts it automatically if it ever stops (configured by the installer's recovery settings).

var builder = Host.CreateApplicationBuilder(args);

builder.Services.AddWindowsService(options =>
{
    options.ServiceName = ShieldWorker.ServiceName;
});

// Log to the Windows Event Log when running as a service; console when run interactively.
builder.Logging.AddEventLog(settings => settings.SourceName = ShieldWorker.ServiceName);

builder.Services.AddHostedService<ShieldWorker>();

var host = builder.Build();
host.Run();
