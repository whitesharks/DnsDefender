using System.Diagnostics;
using System.Reflection;
using DnsDefender.Common.Models;
using DnsDefender.Collector.Services;
using DnsDefender.Collector.Storage;

namespace DnsDefender.Collector.Tests;

public class DnsCollectorServiceDedupTests
{
    [Fact]
    public void DuplicateRecordWithinWindow_IsDeduplicated()
    {
        var dbPath = Path.Combine(Path.GetTempPath(), $"dnsdefender_{Guid.NewGuid():N}.db");
        try
        {
            var repository = new TelemetryRepository(dbPath);
            repository.Initialize();
            using var service = new DnsCollectorService(repository);

            var invoke = typeof(DnsCollectorService).GetMethod("OnDnsRecordCaptured", BindingFlags.Instance | BindingFlags.NonPublic);
            Assert.NotNull(invoke);

            var t = DateTime.UtcNow;
            var first = new DnsTelemetryRecord
            {
                TimestampUtc = t,
                Domain = "example.com",
                QueryType = "A",
                ReturnedIps = "1.1.1.1",
                Source = "ETW",
                RawSummary = "r1"
            };

            var second = new DnsTelemetryRecord
            {
                TimestampUtc = t,
                Domain = "example.com",
                QueryType = "A",
                ReturnedIps = "1.1.1.1",
                Source = "ETW",
                RawSummary = "r1"
            };

            invoke!.Invoke(service, new object[] { first });
            invoke.Invoke(service, new object[] { second });

            var result = repository.Search("example.com", t.AddMinutes(-1), t.AddMinutes(1), 100);
            Assert.Single(result);
        }
        finally
        {
            if (File.Exists(dbPath))
            {
                try { File.Delete(dbPath); } catch { }
            }
        }
    }

    [Fact]
    public void SameDomainDifferentAnswer_IsNotDeduplicated()
    {
        var dbPath = Path.Combine(Path.GetTempPath(), $"dnsdefender_{Guid.NewGuid():N}.db");
        try
        {
            var repository = new TelemetryRepository(dbPath);
            repository.Initialize();
            using var service = new DnsCollectorService(repository);

            var invoke = typeof(DnsCollectorService).GetMethod("OnDnsRecordCaptured", BindingFlags.Instance | BindingFlags.NonPublic);
            Assert.NotNull(invoke);

            var t = DateTime.UtcNow;
            var first = new DnsTelemetryRecord
            {
                TimestampUtc = t,
                Domain = "example.com",
                QueryType = "A",
                ReturnedIps = "1.1.1.1",
                Source = "ETW",
                RawSummary = "r1"
            };

            var second = new DnsTelemetryRecord
            {
                TimestampUtc = t.AddMilliseconds(100),
                Domain = "example.com",
                QueryType = "A",
                ReturnedIps = "2.2.2.2",
                Source = "ETW",
                RawSummary = "r2"
            };

            invoke!.Invoke(service, new object[] { first });
            invoke.Invoke(service, new object[] { second });

            var result = repository.Search("example.com", t.AddMinutes(-1), t.AddMinutes(1), 100);
            Assert.Equal(2, result.Count);
        }
        finally
        {
            if (File.Exists(dbPath))
            {
                try { File.Delete(dbPath); } catch { }
            }
        }
    }

    [Fact]
    public void PcapRecordWithoutPid_UsesCorrelationToFillProcess()
    {
        var dbPath = Path.Combine(Path.GetTempPath(), $"dnsdefender_{Guid.NewGuid():N}.db");
        try
        {
            var repository = new TelemetryRepository(dbPath);
            repository.Initialize();
            using var service = new DnsCollectorService(repository);

            var invoke = typeof(DnsCollectorService).GetMethod("OnDnsRecordCaptured", BindingFlags.Instance | BindingFlags.NonPublic);
            var invokeNameResolution = typeof(DnsCollectorService).GetMethod("OnNameResolutionCaptured", BindingFlags.Instance | BindingFlags.NonPublic);
            Assert.NotNull(invoke);
            Assert.NotNull(invokeNameResolution);

            var pid = Process.GetCurrentProcess().Id;
            var t = DateTime.UtcNow;

            var seed = new DnsTelemetryRecord
            {
                TimestampUtc = t,
                Domain = "www.example.com",
                QueryType = "A",
                ProcessId = pid,
                Source = "NameResolution",
                RawSummary = "seed"
            };

            var pcap = new DnsTelemetryRecord
            {
                TimestampUtc = t.AddMilliseconds(300),
                Domain = "www.example.com",
                QueryType = "A",
                Source = "PCAP",
                RawSummary = "pcap"
            };

            invokeNameResolution!.Invoke(service, new object[] { seed });
            invoke!.Invoke(service, new object[] { pcap });

            var result = repository.Search("www.example.com", t.AddMinutes(-1), t.AddMinutes(1), 100);
            var pcapRecord = result.First(x => x.Source == "PCAP");

            Assert.Equal(pid, pcapRecord.ProcessId);
            Assert.Equal(AttributionStatus.Correlated, pcapRecord.AttributionStatus);
            Assert.False(string.IsNullOrWhiteSpace(pcapRecord.ProcessName));
            Assert.False(string.IsNullOrWhiteSpace(pcapRecord.ExecutablePath));
        }
        finally
        {
            if (File.Exists(dbPath))
            {
                try { File.Delete(dbPath); } catch { }
            }
        }
    }

    [Fact]
    public void PcapRecordEarlierThanNameResolution_IsBackfilled()
    {
        var dbPath = Path.Combine(Path.GetTempPath(), $"dnsdefender_{Guid.NewGuid():N}.db");
        try
        {
            var repository = new TelemetryRepository(dbPath);
            repository.Initialize();
            using var service = new DnsCollectorService(repository);

            var invoke = typeof(DnsCollectorService).GetMethod("OnDnsRecordCaptured", BindingFlags.Instance | BindingFlags.NonPublic);
            var invokeNameResolution = typeof(DnsCollectorService).GetMethod("OnNameResolutionCaptured", BindingFlags.Instance | BindingFlags.NonPublic);
            Assert.NotNull(invoke);
            Assert.NotNull(invokeNameResolution);

            var pid = Process.GetCurrentProcess().Id;
            var t = DateTime.UtcNow;

            var pcap = new DnsTelemetryRecord
            {
                TimestampUtc = t,
                Domain = "cube.weixinbridge.com",
                QueryType = "A",
                Source = "PCAP",
                RawSummary = "pcap"
            };

            var seed = new DnsTelemetryRecord
            {
                TimestampUtc = t.AddMilliseconds(700),
                Domain = "cube.weixinbridge.com",
                QueryType = "A",
                ProcessId = pid,
                Source = "NameResolution",
                RawSummary = "seed"
            };

            invoke!.Invoke(service, new object[] { pcap });
            invokeNameResolution!.Invoke(service, new object[] { seed });

            var result = repository.Search("cube.weixinbridge.com", t.AddMinutes(-1), t.AddMinutes(1), 100);
            var pcapRecord = result.First(x => x.Source == "PCAP");

            Assert.Equal(pid, pcapRecord.ProcessId);
            Assert.Equal(AttributionStatus.Correlated, pcapRecord.AttributionStatus);
            Assert.False(string.IsNullOrWhiteSpace(pcapRecord.ProcessName));
            Assert.False(string.IsNullOrWhiteSpace(pcapRecord.ExecutablePath));
        }
        finally
        {
            if (File.Exists(dbPath))
            {
                try { File.Delete(dbPath); } catch { }
            }
        }
    }
}
