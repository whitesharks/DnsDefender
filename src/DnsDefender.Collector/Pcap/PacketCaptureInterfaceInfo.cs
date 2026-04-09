namespace DnsDefender.Collector.Pcap;

public sealed class PacketCaptureInterfaceInfo
{
    public string InterfaceId { get; init; } = string.Empty;

    public string DisplayName { get; init; } = string.Empty;

    public override string ToString() => DisplayName;
}
