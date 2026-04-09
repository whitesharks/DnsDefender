namespace DnsDefender.Collector.Services;

public sealed class CaptureStartOptions
{
    public bool EnablePacketCapture { get; init; }

    public string PacketCaptureInterfaceId { get; init; } = string.Empty;
}
