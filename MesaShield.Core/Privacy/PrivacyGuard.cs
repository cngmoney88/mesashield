namespace MesaShield.Core.Privacy;

/// <summary>How much MesaShield is allowed to talk to the network.</summary>
public enum PrivacyMode
{
    /// <summary>Signature + app updates allowed; cloud reputation only if the user set a key.</summary>
    Standard,
    /// <summary>No file fingerprints ever leave the machine — cloud reputation is hard-blocked.
    /// Definition and app updates (which send no user data) are still allowed.</summary>
    Strict,
    /// <summary>MesaShield makes zero internet connections. Updates come only from a local mirror.</summary>
    Offline,
}

/// <summary>What a given outbound request is for — used for policy and the audit log.</summary>
public enum NetworkPurpose { SignatureUpdate, AppUpdate, CloudReputation, Other }

/// <summary>One recorded outbound attempt (for the privacy audit trail).</summary>
public sealed record NetworkAuditEntry(
    DateTimeOffset At, string Host, NetworkPurpose Purpose, bool Allowed, string Reason);

/// <summary>
/// The single chokepoint for MesaShield's network policy. Every outbound HTTP request is
/// classified, checked against the current privacy mode, and recorded — so the app both
/// enforces the user's choice and can prove exactly what it did or didn't contact.
/// </summary>
public sealed class PrivacyGuard
{
    public PrivacyMode Mode { get; set; } = PrivacyMode.Standard;

    /// <summary>Raised for every decision so the app can persist an audit log.</summary>
    public event Action<NetworkAuditEntry>? Decision;

    public static NetworkPurpose Classify(string host)
    {
        host = host.ToLowerInvariant();
        if (host.Contains("abuse.ch") || host.Contains("malwarebazaar")) return NetworkPurpose.SignatureUpdate;
        if (host.Contains("virustotal")) return NetworkPurpose.CloudReputation;
        if (host.Contains("github")) return NetworkPurpose.AppUpdate;
        return NetworkPurpose.Other;
    }

    /// <summary>Decide whether a request to <paramref name="host"/> may proceed.</summary>
    public (bool Allowed, string Reason) Evaluate(string host)
    {
        var purpose = Classify(host);
        var (allowed, reason) = Mode switch
        {
            PrivacyMode.Offline => (false, "Offline mode: all internet access is disabled."),
            PrivacyMode.Strict when purpose == NetworkPurpose.CloudReputation =>
                (false, "Strict mode: cloud reputation (sends a file fingerprint) is blocked."),
            PrivacyMode.Strict => (true, "Strict mode: definition/app update sends no user data."),
            _ => (true, "Standard mode."),
        };
        Decision?.Invoke(new NetworkAuditEntry(DateTimeOffset.UtcNow, host, purpose, allowed, reason));
        return (allowed, reason);
    }
}

/// <summary>
/// A DelegatingHandler that runs every HTTP request through the <see cref="PrivacyGuard"/>.
/// Blocked requests never leave the machine — they fail fast with a clear message the callers
/// already handle by degrading gracefully.
/// </summary>
public sealed class PrivacyHandler : DelegatingHandler
{
    private readonly PrivacyGuard _guard;

    public PrivacyHandler(PrivacyGuard guard, HttpMessageHandler inner) : base(inner) => _guard = guard;

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var host = request.RequestUri?.Host ?? "";
        var (allowed, reason) = _guard.Evaluate(host);
        if (!allowed)
            throw new HttpRequestException($"MesaShield privacy policy blocked a connection to {host}. {reason}");
        return base.SendAsync(request, cancellationToken);
    }
}
