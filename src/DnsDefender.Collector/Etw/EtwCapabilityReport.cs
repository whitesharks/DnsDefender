namespace DnsDefender.Collector.Etw;

public sealed class EtwCapabilityReport
{
    public bool IsAvailable { get; init; }

    public string Message { get; init; } = string.Empty;
}
