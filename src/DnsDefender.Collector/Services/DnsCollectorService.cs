using System.Collections.Concurrent;
using DnsDefender.Common.Models;
using DnsDefender.Collector.Attribution;
using DnsDefender.Collector.Correlation;
using DnsDefender.Collector.Etw;
using DnsDefender.Collector.Fallback;
using DnsDefender.Collector.Storage;
using DnsDefender.Collector.Pcap;

namespace DnsDefender.Collector.Services;

public sealed class DnsCollectorService : IDisposable
{
    private readonly DnsEtwSessionManager _dnsEtwSessionManager;
    private readonly NameResolutionEtwSessionManager _nameResolutionEtwSessionManager;
    private readonly DnsOperationalLogWatcher _operationalWatcher;
    private readonly ProcessAttributionService _attributionService;
    private readonly TelemetryRepository _repository;
    private readonly PacketCaptureDnsWatcher _packetCaptureWatcher;
    private readonly DomainProcessCorrelationStore _correlationStore;
    private readonly ConcurrentDictionary<string, DateTime> _recentSeen = new();
    private readonly ConcurrentQueue<DnsTelemetryRecord> _pendingPcapRecords = new();
    private readonly TimeSpan _dedupWindow = TimeSpan.FromMilliseconds(600);
    private readonly TimeSpan _pcapPendingWindow = TimeSpan.FromSeconds(10);

    public DnsCollectorService(TelemetryRepository repository)
    {
        _repository = repository;
        _dnsEtwSessionManager = new DnsEtwSessionManager();
        _nameResolutionEtwSessionManager = new NameResolutionEtwSessionManager();
        _operationalWatcher = new DnsOperationalLogWatcher();
        _attributionService = new ProcessAttributionService();
        _correlationStore = new DomainProcessCorrelationStore();
        _packetCaptureWatcher = new PacketCaptureDnsWatcher();

        _dnsEtwSessionManager.DnsRecordCaptured += OnDnsRecordCaptured;
        _nameResolutionEtwSessionManager.DnsRecordCaptured += OnNameResolutionCaptured;
        _nameResolutionEtwSessionManager.DnsRecordCaptured += OnDnsRecordCaptured;
        _operationalWatcher.DnsRecordCaptured += OnDnsRecordCaptured;
        _packetCaptureWatcher.DnsRecordCaptured += OnDnsRecordCaptured;
    }

    public EtwCapabilityReport ProbeEtwCapability()
    {
        return _dnsEtwSessionManager.ProbeCapability();
    }

    public EtwCapabilityReport ProbeFallbackCapability()
    {
        return _operationalWatcher.ProbeCapability();
    }

    public EtwCapabilityReport GetRuntimeEtwCapability()
    {
        return _dnsEtwSessionManager.GetRuntimeCapabilityReport();
    }

    public IReadOnlyList<PacketCaptureInterfaceInfo> GetPacketCaptureInterfaces()
    {
        return _packetCaptureWatcher.GetInterfaces();
    }

    public CaptureStartResult StartWithFallback(CaptureStartOptions? options = null)
    {
        _repository.Initialize();

        options ??= new CaptureStartOptions();

        var dnsEtwProbe = ProbeEtwCapability();
        var nameEtwProbe = _nameResolutionEtwSessionManager.ProbeCapability();
        var fallbackProbe = ProbeFallbackCapability();
        var packetCaptureMessage = "未启用抓包。";
        var packetCaptureStarted = false;

        if (dnsEtwProbe.IsAvailable)
        {
            _dnsEtwSessionManager.Start();

            var modes = new List<string> { "ETW" };

            if (nameEtwProbe.IsAvailable)
            {
                _nameResolutionEtwSessionManager.Start();
                modes.Add("NameResolution");
            }

            if (fallbackProbe.IsAvailable)
            {
                _operationalWatcher.Start();
                modes.Add("DNS-Operational");
            }

            if (options.EnablePacketCapture)
            {
                packetCaptureMessage = _packetCaptureWatcher.Start(options.PacketCaptureInterfaceId);
                packetCaptureStarted = _packetCaptureWatcher.IsRunning;
                if (packetCaptureStarted)
                {
                    modes.Add("PCAP");
                }
            }

            var mode = string.Join('+', modes);
            var message = mode switch
            {
                "ETW+NameResolution+DNS-Operational+PCAP" => "正在记录 DNS 请求（ETW + NameResolution + 日志 + 抓包四通道）。",
                "ETW+NameResolution+DNS-Operational" => "正在记录 DNS 请求（ETW + NameResolution + 日志三通道）。",
                "ETW+NameResolution+PCAP" => "正在记录 DNS 请求（ETW + NameResolution + 抓包三通道）。",
                "ETW+DNS-Operational+PCAP" => "正在记录 DNS 请求（ETW + 日志 + 抓包三通道）。",
                "ETW+NameResolution" => "正在记录 DNS 请求（ETW + NameResolution 双通道）。",
                "ETW+DNS-Operational" => "正在记录 DNS 请求（ETW + 日志双通道）。",
                "ETW+PCAP" => "正在记录 DNS 请求（ETW + 抓包双通道）。",
                _ => "正在记录 DNS 请求（ETW 主链路）。"
            };

            return new CaptureStartResult
            {
                Started = true,
                Mode = mode,
                Message = message,
                CapabilityMessage = $"DNS ETW：{dnsEtwProbe.Message}；NameResolution：{nameEtwProbe.Message}；Operational：{fallbackProbe.Message}；PCAP：{packetCaptureMessage}",
                PacketCaptureStarted = packetCaptureStarted,
                PacketCaptureMessage = packetCaptureMessage
            };
        }

        if (fallbackProbe.IsAvailable)
        {
            var modes = new List<string> { "DNS-Operational" };
            _operationalWatcher.Start();

            if (options.EnablePacketCapture)
            {
                packetCaptureMessage = _packetCaptureWatcher.Start(options.PacketCaptureInterfaceId);
                packetCaptureStarted = _packetCaptureWatcher.IsRunning;
                if (packetCaptureStarted)
                {
                    modes.Add("PCAP");
                }
            }

            var mode = string.Join('+', modes);
            var message = mode switch
            {
                "DNS-Operational+PCAP" => "ETW 不可用，已切换到 DNS Operational + 抓包模式。",
                _ => "ETW 不可用，已切换到 DNS Operational 日志模式。"
            };

            return new CaptureStartResult
            {
                Started = true,
                Mode = mode,
                Message = message,
                CapabilityMessage = $"{fallbackProbe.Message}；PCAP：{packetCaptureMessage}",
                PacketCaptureStarted = packetCaptureStarted,
                PacketCaptureMessage = packetCaptureMessage
            };
        }

        if (options.EnablePacketCapture)
        {
            packetCaptureMessage = _packetCaptureWatcher.Start(options.PacketCaptureInterfaceId);
            packetCaptureStarted = _packetCaptureWatcher.IsRunning;
            if (packetCaptureStarted)
            {
                return new CaptureStartResult
                {
                    Started = true,
                    Mode = "PCAP",
                    Message = "ETW 与日志通道不可用，已切换到抓包模式。",
                    CapabilityMessage = $"DNS ETW：{dnsEtwProbe.Message}；NameResolution：{nameEtwProbe.Message}；降级：{fallbackProbe.Message}；PCAP：{packetCaptureMessage}",
                    PacketCaptureStarted = true,
                    PacketCaptureMessage = packetCaptureMessage
                };
            }
        }

        return new CaptureStartResult
        {
            Started = false,
            Mode = "None",
            Message = "未开始记录。ETW、降级数据源与抓包均不可用。",
            CapabilityMessage = $"DNS ETW：{dnsEtwProbe.Message}；NameResolution：{nameEtwProbe.Message}；降级：{fallbackProbe.Message}；PCAP：{packetCaptureMessage}",
            PacketCaptureStarted = false,
            PacketCaptureMessage = packetCaptureMessage
        };
    }

    public void Stop()
    {
        _dnsEtwSessionManager.Stop();
        _nameResolutionEtwSessionManager.Stop();
        _operationalWatcher.Stop();
        _packetCaptureWatcher.Stop();
    }

    private void OnNameResolutionCaptured(DnsTelemetryRecord record)
    {
        var pid = record.ProcessId;
        if (!pid.HasValue || pid.Value <= 0)
        {
            return;
        }

        var resolved = _attributionService.Resolve(pid.Value);
        _correlationStore.AddAliases(record.Domain, pid.Value, resolved.ProcessName, resolved.ExecutablePath, record.TimestampUtc);
        TryBackfillPendingPcapRecords(record.Domain, record.TimestampUtc);
    }

    private void OnDnsRecordCaptured(DnsTelemetryRecord record)
    {
        if (string.Equals(record.Domain, "system.byte", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        var normalizedDomain = record.Domain.Trim().TrimEnd('.').ToLowerInvariant();
        if (string.IsNullOrWhiteSpace(normalizedDomain))
        {
            return;
        }

        record.Domain = normalizedDomain;

        var queryType = string.IsNullOrWhiteSpace(record.QueryType) ? "?" : record.QueryType.Trim().ToUpperInvariant();
        var processIdPart = record.ProcessId?.ToString() ?? "?";
        var answerPart = string.IsNullOrWhiteSpace(record.ReturnedIps) ? "?" : record.ReturnedIps.Trim().ToLowerInvariant();
        var dedupBucket = record.TimestampUtc.Ticks / TimeSpan.FromMilliseconds(250).Ticks;
        var dedupKey = $"{record.Source}|{normalizedDomain}|{queryType}|{processIdPart}|{answerPart}|{dedupBucket}";
        if (_recentSeen.TryGetValue(dedupKey, out var seenAt) && record.TimestampUtc - seenAt < _dedupWindow)
        {
            return;
        }

        _recentSeen[dedupKey] = record.TimestampUtc;
        CleanupRecentSeen(record.TimestampUtc);

        if (record.Source == "DNS-Operational" && record.ProcessId is > 0)
        {
            var resolvedFromOperational = _attributionService.Resolve(record.ProcessId.Value);
            if (!string.IsNullOrWhiteSpace(resolvedFromOperational.ProcessName))
            {
                _correlationStore.AddAliases(record.Domain, record.ProcessId.Value, resolvedFromOperational.ProcessName, resolvedFromOperational.ExecutablePath, record.TimestampUtc);
            }
        }

        var resolvedProcessId = record.ProcessId;
        var resolvedProcess = _attributionService.Resolve(resolvedProcessId);
        var existingProcessName = record.ProcessName;
        var existingExecutablePath = record.ExecutablePath;

        var isResolverProcess = string.Equals(resolvedProcess.ProcessName, "svchost", StringComparison.OrdinalIgnoreCase);
        var sourceCanUseCorrelation = record.Source == "ETW" || record.Source == "PCAP";
        var needsCorrelation = resolvedProcessId is null || isResolverProcess || string.IsNullOrWhiteSpace(resolvedProcess.ProcessName);

        if (sourceCanUseCorrelation && needsCorrelation)
        {
            var match = _correlationStore.FindBestMatch(record.Domain, record.TimestampUtc, TimeSpan.FromSeconds(10));
            if (match is not null && !string.Equals(match.ProcessName, "svchost", StringComparison.OrdinalIgnoreCase))
            {
                resolvedProcessId = match.ProcessId;
                resolvedProcess = (match.ProcessName, match.ExecutablePath);
                record.AttributionStatus = AttributionStatus.Correlated;
                record.AttributionConfidence = record.Source == "PCAP" ? 0.35 : 0.95;
            }
        }

        record.ProcessId = resolvedProcessId;
        record.ProcessName = string.IsNullOrWhiteSpace(resolvedProcess.ProcessName)
            ? existingProcessName
            : resolvedProcess.ProcessName;
        record.ExecutablePath = string.IsNullOrWhiteSpace(resolvedProcess.ExecutablePath)
            ? existingExecutablePath
            : resolvedProcess.ExecutablePath;

        if (record.AttributionStatus != AttributionStatus.Correlated)
        {
            if (resolvedProcessId is not null && !string.IsNullOrWhiteSpace(record.ProcessName))
            {
                record.AttributionStatus = AttributionStatus.Direct;
                record.AttributionConfidence = record.Source == "ETW" ? 1.0 : Math.Max(record.AttributionConfidence, 0.7);
            }
            else
            {
                record.AttributionStatus = AttributionStatus.Unavailable;
                record.AttributionConfidence = 0;
            }
        }

        var insertedId = _repository.Insert(record);
        record.Id = insertedId;

        if (record.Source == "PCAP" && record.AttributionStatus == AttributionStatus.Unavailable)
        {
            EnqueuePendingPcap(record);
        }

        if (record.Source != "PCAP" && record.ProcessId is > 0 && !string.IsNullOrWhiteSpace(record.ProcessName))
        {
            _correlationStore.AddAliases(record.Domain, record.ProcessId.Value, record.ProcessName, record.ExecutablePath, record.TimestampUtc);
            TryBackfillPendingPcapRecords(record.Domain, record.TimestampUtc);
        }
    }

    private void EnqueuePendingPcap(DnsTelemetryRecord record)
    {
        _pendingPcapRecords.Enqueue(new DnsTelemetryRecord
        {
            Id = record.Id,
            TimestampUtc = record.TimestampUtc,
            Domain = record.Domain,
            QueryType = record.QueryType,
            ResponseCode = record.ResponseCode,
            ReturnedIps = record.ReturnedIps,
            ProcessId = record.ProcessId,
            ProcessName = record.ProcessName,
            ExecutablePath = record.ExecutablePath,
            AttributionStatus = record.AttributionStatus,
            AttributionConfidence = record.AttributionConfidence,
            Source = record.Source,
            RawSummary = record.RawSummary
        });

        CleanupPendingPcap(record.TimestampUtc);
    }

    private void TryBackfillPendingPcapRecords(string domain, DateTime referenceTimeUtc)
    {
        if (string.IsNullOrWhiteSpace(domain))
        {
            return;
        }

        CleanupPendingPcap(referenceTimeUtc);

        var domainCandidates = BuildDomainCandidates(domain);
        var pendingCount = _pendingPcapRecords.Count;
        for (var i = 0; i < pendingCount; i++)
        {
            if (!_pendingPcapRecords.TryDequeue(out var pending))
            {
                break;
            }

            var age = referenceTimeUtc - pending.TimestampUtc;
            if (age > _pcapPendingWindow)
            {
                continue;
            }

            if (age < TimeSpan.FromSeconds(-15))
            {
                _pendingPcapRecords.Enqueue(pending);
                continue;
            }

            if (!domainCandidates.Contains(pending.Domain))
            {
                _pendingPcapRecords.Enqueue(pending);
                continue;
            }

            var match = _correlationStore.FindBestMatch(pending.Domain, pending.TimestampUtc, TimeSpan.FromSeconds(10));
            if (match is null || string.Equals(match.ProcessName, "svchost", StringComparison.OrdinalIgnoreCase))
            {
                _pendingPcapRecords.Enqueue(pending);
                continue;
            }

            _repository.UpdateAttributionById(
                pending.Id,
                match.ProcessId,
                match.ProcessName,
                match.ExecutablePath,
                AttributionStatus.Correlated,
                0.35);
        }
    }

    private HashSet<string> BuildDomainCandidates(string domain)
    {
        var normalized = domain.Trim().TrimEnd('.').ToLowerInvariant();
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { normalized };

        var parts = normalized.Split('.', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length >= 3)
        {
            for (var i = 1; i < parts.Length - 1; i++)
            {
                set.Add(string.Join('.', parts[i..]));
            }
        }

        return set;
    }

    private void CleanupPendingPcap(DateTime nowUtc)
    {
        while (_pendingPcapRecords.TryPeek(out var item) && nowUtc - item.TimestampUtc > _pcapPendingWindow)
        {
            _pendingPcapRecords.TryDequeue(out _);
        }
    }

    private void CleanupRecentSeen(DateTime nowUtc)
    {
        var cutoff = nowUtc - TimeSpan.FromSeconds(10);
        foreach (var kv in _recentSeen)
        {
            if (kv.Value < cutoff)
            {
                _recentSeen.TryRemove(kv.Key, out _);
            }
        }
    }

    public void Dispose()
    {
        _dnsEtwSessionManager.DnsRecordCaptured -= OnDnsRecordCaptured;
        _nameResolutionEtwSessionManager.DnsRecordCaptured -= OnNameResolutionCaptured;
        _nameResolutionEtwSessionManager.DnsRecordCaptured -= OnDnsRecordCaptured;
        _operationalWatcher.DnsRecordCaptured -= OnDnsRecordCaptured;
        _packetCaptureWatcher.DnsRecordCaptured -= OnDnsRecordCaptured;
        _dnsEtwSessionManager.Dispose();
        _nameResolutionEtwSessionManager.Dispose();
        _operationalWatcher.Dispose();
        _packetCaptureWatcher.Dispose();
    }
}
