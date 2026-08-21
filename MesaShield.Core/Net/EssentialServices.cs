namespace MesaShield.Core.Net;

/// <summary>
/// Heuristics for "this connection is core OS/network plumbing, not something to block."
/// Used so egress control doesn't fight DNS, time sync, or Windows Update. It's intentionally
/// conservative — a small, well-understood set — and everything else is decided by what the
/// machine has actually learned as normal plus the user's own allowlist.
/// </summary>
public static class EssentialServices
{
    // Ports that are infrastructure, not data channels.
    private static readonly HashSet<int> InfraPorts = new() { 53, 67, 68, 123, 137, 138, 139, 5353 };

    // System processes that legitimately talk to the network for the OS itself.
    private static readonly HashSet<string> SystemProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "svchost", "system", "lsass", "services", "wuauclt", "MoUsoCoreWorker", "usocoreworker",
        "SearchHost", "backgroundTaskHost", "dnscache", "ntoskrnl",
    };

    // MesaShield's OWN processes — must ALWAYS be allowed out so the product can update itself,
    // pull signatures, and reach its cloud reputation service. Blocking these was self-sabotage
    // (it once blocked its own connection to GitHub and could never auto-update).
    private static readonly HashSet<string> SelfProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "MesaShield", "MesaShield.App", "MesaShield.Service",
    };

    // Domains/suffixes that are core Microsoft/OS or well-known infrastructure. Matched against a
    // resolved hostname when one is available (best-effort — IP-only connections rely on the ports
    // and system-process checks instead).
    private static readonly string[] EssentialHostSuffixes =
    {
        "windowsupdate.com", "update.microsoft.com", "microsoft.com", "windows.com",
        "msftconnecttest.com", "msftncsi.com", "time.windows.com", "ntp.org",
        "digicert.com", "verisign.com", "sectigo.com",  // certificate revocation / OCSP
        // MesaShield's own update + signature + reputation infrastructure.
        "github.com", "githubusercontent.com", "abuse.ch", "virustotal.com",
    };

    public static bool IsInfraPort(int port) => InfraPorts.Contains(port);

    public static bool IsSystemProcess(string processName) =>
        SystemProcesses.Contains(processName.Replace(".exe", "", StringComparison.OrdinalIgnoreCase));

    /// <summary>MesaShield's own processes — never treated as data exfiltration.</summary>
    public static bool IsSelf(string processName) =>
        SelfProcesses.Contains(processName.Replace(".exe", "", StringComparison.OrdinalIgnoreCase));

    public static bool IsEssentialHost(string? resolvedHost)
    {
        if (string.IsNullOrEmpty(resolvedHost)) return false;
        var h = resolvedHost.ToLowerInvariant();
        return EssentialHostSuffixes.Any(s => h == s || h.EndsWith("." + s));
    }

    /// <summary>True if this connection is core plumbing we should never treat as data exfiltration.</summary>
    public static bool IsEssential(string processName, int remotePort, string? resolvedHost) =>
        IsSelf(processName) || IsInfraPort(remotePort) || IsSystemProcess(processName) || IsEssentialHost(resolvedHost);
}
