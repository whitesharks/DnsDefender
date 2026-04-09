using DnsDefender.Collector.Pcap;

namespace DnsDefender.Collector.Tests;

public class PacketCaptureAttributionTests
{
    [Fact]
    public void Start_WithEmptyInterface_ReturnsFriendlyMessage()
    {
        using var watcher = new PacketCaptureDnsWatcher();
        var msg = watcher.Start(string.Empty);
        Assert.Contains("未选择抓包网卡", msg);
    }

    [Fact]
    public void Start_WithInvalidInterface_ReturnsHintOrNotFoundMessage()
    {
        using var watcher = new PacketCaptureDnsWatcher();
        var msg = watcher.Start("invalid-interface-id");
        Assert.True(
            msg.Contains("未找到所选网卡") ||
            msg.Contains("Npcap", StringComparison.OrdinalIgnoreCase) ||
            msg.Contains("https://npcap.com/#download", StringComparison.OrdinalIgnoreCase));
    }
}
