namespace DnsDefender.Collector.Services;

public sealed class CaptureStartResult
{
    public bool Started { get; init; }

    public string Mode { get; init; } = string.Empty;

    public string Message { get; init; } = string.Empty;

    public string CapabilityMessage { get; init; } = string.Empty;

    public bool PacketCaptureStarted { get; init; }

    public string PacketCaptureMessage { get; init; } = string.Empty;
}
