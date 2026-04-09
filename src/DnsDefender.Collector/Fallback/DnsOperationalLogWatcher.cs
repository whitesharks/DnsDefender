using System.Diagnostics.Eventing.Reader;
using System.Text.RegularExpressions;
using DnsDefender.Common.Models;
using DnsDefender.Collector.Etw;
using DnsDefender.Collector.Parsing;

namespace DnsDefender.Collector.Fallback;

public sealed class DnsOperationalLogWatcher : IDisposable
{
    private const string LogName = "Microsoft-Windows-DNS-Client/Operational";
    private static readonly Regex Ipv4Regex = new(@"\b(?:\d{1,3}\.){3}\d{1,3}\b", RegexOptions.Compiled);
    private static readonly Regex Ipv6Regex = new(@"\b(?:(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}|::1|::)\b", RegexOptions.Compiled);

    private EventLogWatcher? _watcher;

    public event Action<DnsTelemetryRecord>? DnsRecordCaptured;

    public bool IsRunning { get; private set; }

    public EtwCapabilityReport ProbeCapability()
    {
        if (!OperatingSystem.IsWindows())
        {
            return new EtwCapabilityReport
            {
                IsAvailable = false,
                Message = "DNS Operational 日志在非 Windows 系统不可用。"
            };
        }

        try
        {
            using var _ = new EventLogSession();
            return new EtwCapabilityReport
            {
                IsAvailable = true,
                Message = "DNS Operational 日志可用（降级模式）。"
            };
        }
        catch (Exception ex)
        {
            return new EtwCapabilityReport
            {
                IsAvailable = false,
                Message = $"DNS Operational 日志不可用：{ex.Message}"
            };
        }
    }

    public void Start()
    {
        if (IsRunning)
        {
            return;
        }

        var query = new EventLogQuery(LogName, PathType.LogName, "*[System[(Level=0 or Level=4 or Level=5)]]")
        {
            ReverseDirection = false,
            TolerateQueryErrors = true
        };

        _watcher = new EventLogWatcher(query);
        _watcher.EventRecordWritten += OnEventRecordWritten;
        _watcher.Enabled = true;
        IsRunning = true;
    }

    public void Stop()
    {
        if (!IsRunning)
        {
            return;
        }

        if (_watcher is not null)
        {
            _watcher.EventRecordWritten -= OnEventRecordWritten;
            _watcher.Enabled = false;
            _watcher.Dispose();
            _watcher = null;
        }

        IsRunning = false;
    }

    private void OnEventRecordWritten(object? sender, EventRecordWrittenEventArgs e)
    {
        if (e.EventException is not null || e.EventRecord is null)
        {
            return;
        }

        using var record = e.EventRecord;

        string description;
        try
        {
            description = record.FormatDescription() ?? string.Empty;
        }
        catch
        {
            description = string.Empty;
        }

        var domain = DnsDomainExtractor.ExtractFromOperational(description, record.Properties);
        if (string.IsNullOrWhiteSpace(domain))
        {
            return;
        }

        var ips = string.Join(';', Ipv4Regex.Matches(description).Select(m => m.Value)
            .Concat(Ipv6Regex.Matches(description).Select(m => m.Value))
            .Distinct());
        var pid = TryReadProcessId(record, description);

        DnsRecordCaptured?.Invoke(new DnsTelemetryRecord
        {
            TimestampUtc = (record.TimeCreated ?? DateTime.Now).ToUniversalTime(),
            Domain = domain.Trim().TrimEnd('.').ToLowerInvariant(),
            QueryType = ExtractQueryType(description),
            ResponseCode = record.Id.ToString(),
            ReturnedIps = ips,
            ProcessId = pid,
            AttributionStatus = pid.HasValue ? AttributionStatus.Direct : AttributionStatus.Unavailable,
            AttributionConfidence = pid.HasValue ? 0.9 : 0,
            Source = "DNS-Operational",
            RawSummary = description
        });
    }

    private static int? TryReadProcessId(EventRecord record, string description)
    {
        if (record.ProcessId is > 0)
        {
            return record.ProcessId;
        }

        foreach (var prop in record.Properties)
        {
            if (prop.Value is null)
            {
                continue;
            }

            if (int.TryParse(prop.Value.ToString(), out var pidFromProp) && pidFromProp > 4)
            {
                return pidFromProp;
            }
        }

        var pidMatch = Regex.Match(description, @"\bPID\D+(\d{2,10})\b", RegexOptions.IgnoreCase);
        if (pidMatch.Success && int.TryParse(pidMatch.Groups[1].Value, out var pidFromText) && pidFromText > 4)
        {
            return pidFromText;
        }

        return null;
    }


    private static string ExtractQueryType(string description)
    {
        if (description.Contains(" HTTPS", StringComparison.OrdinalIgnoreCase))
        {
            return "HTTPS";
        }

        if (description.Contains(" SVCB", StringComparison.OrdinalIgnoreCase))
        {
            return "SVCB";
        }

        if (description.Contains(" AAAA", StringComparison.OrdinalIgnoreCase))
        {
            return "AAAA";
        }

        if (description.Contains(" A ", StringComparison.OrdinalIgnoreCase) || description.EndsWith(" A", StringComparison.OrdinalIgnoreCase))
        {
            return "A";
        }

        if (description.Contains(" CNAME", StringComparison.OrdinalIgnoreCase))
        {
            return "CNAME";
        }

        if (description.Contains(" TXT", StringComparison.OrdinalIgnoreCase))
        {
            return "TXT";
        }

        if (description.Contains(" PTR", StringComparison.OrdinalIgnoreCase))
        {
            return "PTR";
        }

        if (description.Contains(" SRV", StringComparison.OrdinalIgnoreCase))
        {
            return "SRV";
        }

        return string.Empty;
    }

    public void Dispose()
    {
        Stop();
    }
}
