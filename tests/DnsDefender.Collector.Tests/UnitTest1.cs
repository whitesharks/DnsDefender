using DnsDefender.Common.Models;
using DnsDefender.Collector.Storage;

namespace DnsDefender.Collector.Tests;

public class UnitTest1
{
    [Fact]
    public void Repository_CanInsertAndSearchByDomain()
    {
        var dbPath = Path.Combine(Path.GetTempPath(), $"dnsdefender_{Guid.NewGuid():N}.db");

        try
        {
            var repository = new TelemetryRepository(dbPath);
            repository.Initialize();

            repository.Insert(new DnsTelemetryRecord
            {
                TimestampUtc = DateTime.UtcNow,
                Domain = "malicious-c2.example",
                QueryType = "A",
                ResponseCode = "0",
                ReturnedIps = "1.2.3.4",
                ProcessId = 1234,
                ProcessName = "powershell",
                ExecutablePath = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                AttributionStatus = AttributionStatus.Direct,
                AttributionConfidence = 1,
                Source = "ETW",
                RawSummary = "test"
            });

            repository.Insert(new DnsTelemetryRecord
            {
                TimestampUtc = DateTime.UtcNow,
                Domain = "normal.example",
                QueryType = "A",
                ResponseCode = "0",
                ReturnedIps = "8.8.8.8",
                AttributionStatus = AttributionStatus.Unavailable,
                AttributionConfidence = 0,
                Source = "ETW",
                RawSummary = "test"
            });

            var result = repository.Search("malicious-c2", DateTime.UtcNow.AddHours(-1), DateTime.UtcNow.AddHours(1));

            Assert.Single(result);
            Assert.Equal("malicious-c2.example", result[0].Domain);
            Assert.Equal(1234, result[0].ProcessId);
            Assert.Equal("powershell", result[0].ProcessName);
        }
        finally
        {
            if (File.Exists(dbPath))
            {
                try
                {
                    File.Delete(dbPath);
                }
                catch
                {
                }
            }
        }
    }
}
