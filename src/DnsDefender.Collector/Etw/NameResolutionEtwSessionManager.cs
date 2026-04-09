using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;
using DnsDefender.Common.Models;
using DnsDefender.Collector.Parsing;

namespace DnsDefender.Collector.Etw;

public sealed class NameResolutionEtwSessionManager : IDisposable
{
    private const string ProviderName = "Microsoft-Windows-Winsock-NameResolution";

    private readonly string _sessionName = $"DnsDefenderNameRes_{Environment.ProcessId}";
    private TraceEventSession? _session;
    private Task? _processingTask;
    private CancellationTokenSource? _cts;

    public event Action<DnsTelemetryRecord>? DnsRecordCaptured;

    public bool IsRunning { get; private set; }

    public EtwCapabilityReport ProbeCapability()
    {
        try
        {
            using var probeSession = new TraceEventSession($"DnsDefenderNameResProbe_{Environment.ProcessId}_{Guid.NewGuid():N}")
            {
                StopOnDispose = true
            };

            probeSession.EnableProvider(ProviderName);
            probeSession.DisableProvider(ProviderName);

            return new EtwCapabilityReport
            {
                IsAvailable = true,
                Message = "Winsock 名称解析 ETW 可用。"
            };
        }
        catch (Exception ex)
        {
            return new EtwCapabilityReport
            {
                IsAvailable = false,
                Message = $"Winsock 名称解析 ETW 不可用：{ex.Message}"
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
        _session.Source.Dynamic.All += OnDynamicEvent;
        _processingTask = Task.Run(() => _session.Source.Process(), _cts.Token);
        IsRunning = true;
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

    private void OnDynamicEvent(TraceEvent data)
    {
        if (!string.Equals(data.ProviderName, ProviderName, StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        var domain = DnsDomainExtractor.ExtractFromTraceEvent(
                         data,
                         "QueryName",
                         "NodeName",
                         "Name",
                         "HostName",
                         "Host",
                         "Query")
                     ?? string.Empty;

        if (string.IsNullOrWhiteSpace(domain))
        {
            return;
        }

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

        DnsRecordCaptured?.Invoke(new DnsTelemetryRecord
        {
            TimestampUtc = data.TimeStamp.ToUniversalTime(),
            Domain = domain.Trim().TrimEnd('.').ToLowerInvariant(),
            QueryType = "",
            ResponseCode = "",
            ReturnedIps = "",
            ProcessId = pid,
            AttributionStatus = pid.HasValue ? AttributionStatus.Direct : AttributionStatus.Unavailable,
            AttributionConfidence = pid.HasValue ? 0.95 : 0,
            Source = "NameResolution-ETW",
            RawSummary = data.FormattedMessage ?? data.EventName ?? string.Empty
        });
    }

    private static string? GetPayloadValue(TraceEvent data, string key)
    {
        for (var i = 0; i < data.PayloadNames.Length; i++)
        {
            if (string.Equals(data.PayloadNames[i], key, StringComparison.OrdinalIgnoreCase))
            {
                return data.PayloadValue(i)?.ToString();
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


    public void Dispose()
    {
        Stop();
    }
}
