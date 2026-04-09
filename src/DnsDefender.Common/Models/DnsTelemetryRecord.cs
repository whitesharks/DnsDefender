namespace DnsDefender.Common.Models;

public sealed class DnsTelemetryRecord
{
    public long Id { get; set; }

    public DateTime TimestampUtc { get; set; }

    public DateTime TimestampLocal => TimestampUtc.ToLocalTime();

    public string Domain { get; set; } = string.Empty;

    public string QueryType { get; set; } = string.Empty;

    public string ResponseCode { get; set; } = string.Empty;

    public string ReturnedIps { get; set; } = string.Empty;

    public int? ProcessId { get; set; }

    public string ProcessName { get; set; } = string.Empty;

    public string ExecutablePath { get; set; } = string.Empty;

    public AttributionStatus AttributionStatus { get; set; } = AttributionStatus.Unavailable;

    public string AttributionStatusText => AttributionStatus switch
    {
        AttributionStatus.Direct => "直接归因",
        AttributionStatus.Correlated => "关联归因",
        _ => "无法归因"
    };

    public double AttributionConfidence { get; set; }

    public string Source { get; set; } = string.Empty;

    public string RawSummary { get; set; } = string.Empty;
}
