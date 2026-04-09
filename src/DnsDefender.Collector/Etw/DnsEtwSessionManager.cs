using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;
using DnsDefender.Common.Models;
using DnsDefender.Collector.Parsing;

namespace DnsDefender.Collector.Etw;

public sealed class DnsEtwSessionManager : IDisposable
{
    private const string ProviderName = "Microsoft-Windows-DNS-Client";

    private readonly string _sessionName = $"DnsDefenderSession_{Environment.ProcessId}";
    private TraceEventSession? _session;
    private Task? _processingTask;
    private CancellationTokenSource? _cts;
    private int _eventsSeen;
    private int _eventsWithDomain;
    private int _eventsWithPid;

    public event Action<DnsTelemetryRecord>? DnsRecordCaptured;

    public bool IsRunning { get; private set; }

    public EtwCapabilityReport ProbeCapability()
    {
        if (!OperatingSystem.IsWindows())
        {
            return new EtwCapabilityReport
            {
                IsAvailable = false,
                Message = "非 Windows 系统不支持 ETW。"
            };
        }

        try
        {
            using var probeSession = new TraceEventSession($"DnsDefenderProbe_{Environment.ProcessId}_{Guid.NewGuid():N}")
            {
                StopOnDispose = true
            };

            probeSession.EnableProvider(ProviderName);
            probeSession.DisableProvider(ProviderName);

            return new EtwCapabilityReport
            {
                IsAvailable = true,
                Message = "DNS ETW 提供程序可用。"
            };
        }
        catch (UnauthorizedAccessException)
        {
            return new EtwCapabilityReport
            {
                IsAvailable = false,
                Message = "ETW 需要管理员权限，请以管理员身份运行。"
            };
        }
        catch (Exception ex)
        {
            return new EtwCapabilityReport
            {
                IsAvailable = false,
                Message = $"ETW 探测失败：{ex.Message}"
            };
        }
    }

    public void Start()
    {
        if (IsRunning)
        {
            return;
        }

        _cts = new CancellationTokenSource();
        _session = new TraceEventSession(_sessionName)
        {
            StopOnDispose = true
        };

        _session.EnableProvider(ProviderName);

        _eventsSeen = 0;
        _eventsWithDomain = 0;
        _eventsWithPid = 0;

        _session.Source.Dynamic.All += OnDynamicEvent;
        _processingTask = Task.Run(() => _session.Source.Process(), _cts.Token);
        IsRunning = true;
    }

    private void OnDynamicEvent(TraceEvent data)
    {
        if (!string.Equals(data.ProviderName, ProviderName, StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        var domain = DnsDomainExtractor.ExtractFromTraceEvent(
                         data,
                         "QueryName",
                         "Name",
                         "HostName",
                         "Query",
                         "NodeName",
                         "Host")
                     ?? string.Empty;

        if (string.IsNullOrWhiteSpace(domain))
        {
            return;
        }

        _eventsSeen++;
        _eventsWithDomain++;

        var headerPid = data.ProcessID > 0 ? data.ProcessID : 0;
        var payloadPidText = GetPayloadValue(data, "ProcessId")
                             ?? GetPayloadValue(data, "ProcessID")
                             ?? GetPayloadValue(data, "PID")
                             ?? GetPayloadValue(data, "ClientProcessId")
                             ?? GetPayloadValue(data, "ClientProcessID")
                             ?? GetPayloadValue(data, "ApplicationId")
                             ?? GetPayloadValue(data, "AppId");

        int payloadPid = 0;
        if (!string.IsNullOrWhiteSpace(payloadPidText))
        {
            int.TryParse(payloadPidText, out payloadPid);
        }

        var pid = ChooseBestProcessId(headerPid, payloadPid);
        if (pid.HasValue)
        {
            _eventsWithPid++;
        }

        var queryType = GetPayloadValue(data, "QueryType")
                        ?? GetPayloadValue(data, "Type")
                        ?? GetPayloadValue(data, "QueryRecordType")
                        ?? GetPayloadValue(data, "RecordType")
                        ?? string.Empty;
        var status = GetPayloadValue(data, "Status")
                     ?? GetPayloadValue(data, "QueryStatus")
                     ?? GetPayloadValue(data, "ResultCode")
                     ?? GetPayloadValue(data, "ResponseCode")
                     ?? string.Empty;
        var answers = GetPayloadValue(data, "Results")
                      ?? GetPayloadValue(data, "Result")
                      ?? GetPayloadValue(data, "Answer")
                      ?? GetPayloadValue(data, "Answers")
                      ?? GetPayloadValue(data, "Address")
                      ?? GetPayloadValue(data, "Addresses")
                      ?? string.Empty;

        DnsRecordCaptured?.Invoke(new DnsTelemetryRecord
        {
            TimestampUtc = data.TimeStamp.ToUniversalTime(),
            Domain = domain.Trim().TrimEnd('.').ToLowerInvariant(),
            QueryType = queryType,
            ResponseCode = status,
            ReturnedIps = answers,
            ProcessId = pid,
            AttributionStatus = pid.HasValue ? AttributionStatus.Direct : AttributionStatus.Unavailable,
            AttributionConfidence = pid.HasValue ? 1.0 : 0,
            Source = "ETW",
            RawSummary = data.FormattedMessage ?? data.EventName ?? string.Empty
        });
    }

    private static string? GetPayloadValue(TraceEvent data, string key)
    {
        for (var i = 0; i < data.PayloadNames.Length; i++)
        {
            if (string.Equals(data.PayloadNames[i], key, StringComparison.OrdinalIgnoreCase))
            {
                var raw = data.PayloadValue(i);
                return raw?.ToString();
            }
        }

        return null;
    }

    private static int? ChooseBestProcessId(int headerPid, int payloadPid)
    {
        var h = headerPid > 0 ? headerPid : 0;
        var p = payloadPid > 0 ? payloadPid : 0;

        if (h == 0 && p == 0)
        {
            return null;
        }

        if (h == 0)
        {
            return p;
        }

        if (p == 0)
        {
            return h;
        }

        var hName = TryGetProcessName(h);
        var pName = TryGetProcessName(p);

        if (string.Equals(hName, "svchost", StringComparison.OrdinalIgnoreCase)
            && !string.Equals(pName, "svchost", StringComparison.OrdinalIgnoreCase)
            && !string.IsNullOrWhiteSpace(pName))
        {
            return p;
        }

        if (string.Equals(pName, "svchost", StringComparison.OrdinalIgnoreCase)
            && !string.Equals(hName, "svchost", StringComparison.OrdinalIgnoreCase)
            && !string.IsNullOrWhiteSpace(hName))
        {
            return h;
        }

        return p;
    }

    private static string TryGetProcessName(int pid)
    {
        try
        {
            using var process = System.Diagnostics.Process.GetProcessById(pid);
            return process.ProcessName;
        }
        catch
        {
            return string.Empty;
        }
    }


    public EtwCapabilityReport GetRuntimeCapabilityReport()
    {
        if (!IsRunning)
        {
            return new EtwCapabilityReport
            {
                IsAvailable = true,
                Message = "ETW 已启动，能力尚未采样。"
            };
        }

        if (_eventsSeen == 0)
        {
            return new EtwCapabilityReport
            {
                IsAvailable = true,
                Message = "ETW 运行中，等待 DNS 事件以验证 PID 字段支持。"
            };
        }

        var hasPidSupport = _eventsWithPid > 0;
        return new EtwCapabilityReport
        {
            IsAvailable = true,
            Message = hasPidSupport
                ? $"ETW 运行中，事件总数 {_eventsSeen}，域名解析成功 {_eventsWithDomain}，带 PID 事件 {_eventsWithPid}。"
                : $"ETW 运行中，事件总数 {_eventsSeen}，域名解析成功 {_eventsWithDomain}，当前尚未观察到 PID 字段。"
        };
    }

    public void Stop()
    {
        if (!IsRunning)
        {
            return;
        }

        try
        {
            _cts?.Cancel();
            _session?.Stop();
            _processingTask?.Wait(TimeSpan.FromSeconds(2));
        }
        catch
        {
        }
        finally
        {
            _session?.Dispose();
            _cts?.Dispose();
            _session = null;
            _cts = null;
            _processingTask = null;
            IsRunning = false;
        }
    }

    public void Dispose()
    {
        Stop();
    }
}
