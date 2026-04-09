using System.Collections.Concurrent;

namespace DnsDefender.Collector.Correlation;

public sealed class DomainProcessCorrelationStore
{
    private readonly ConcurrentQueue<CorrelationItem> _items = new();
    private readonly TimeSpan _retention = TimeSpan.FromSeconds(20);

    public void AddAliases(string domain, int processId, string processName, string executablePath, DateTime timestampUtc)
    {
        if (string.IsNullOrWhiteSpace(domain) || processId <= 0)
        {
            return;
        }

        Add(domain, processId, processName, executablePath, timestampUtc);

        var normalized = NormalizeDomain(domain);
        var parts = normalized.Split('.', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 3)
        {
            return;
        }

        for (var i = 1; i < parts.Length - 1; i++)
        {
            Add(string.Join('.', parts[i..]), processId, processName, executablePath, timestampUtc);
        }
    }

    public CorrelationMatch? FindBestMatch(string domain, DateTime timestampUtc, TimeSpan maxDelta)
    {
        if (string.IsNullOrWhiteSpace(domain))
        {
            return null;
        }

        Cleanup(timestampUtc);

        var candidates = BuildCandidateDomains(domain);
        var minTime = timestampUtc - maxDelta;
        var maxTime = timestampUtc + maxDelta;

        CorrelationItem? best = null;
        foreach (var item in _items)
        {
            if (!candidates.Contains(item.Domain))
            {
                continue;
            }

            if (item.TimestampUtc < minTime || item.TimestampUtc > maxTime)
            {
                continue;
            }

            if (best is null || item.TimestampUtc > best.TimestampUtc)
            {
                best = item;
            }
        }

        if (best is null)
        {
            return null;
        }

        return new CorrelationMatch(best.ProcessId, best.ProcessName, best.ExecutablePath, best.TimestampUtc);
    }

    private void Add(string domain, int processId, string processName, string executablePath, DateTime timestampUtc)
    {
        _items.Enqueue(new CorrelationItem(NormalizeDomain(domain), processId, processName, executablePath, timestampUtc));
        Cleanup(timestampUtc);
    }

    private static string NormalizeDomain(string domain)
    {
        return domain.Trim().TrimEnd('.').ToLowerInvariant();
    }

    private static HashSet<string> BuildCandidateDomains(string domain)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var normalized = NormalizeDomain(domain);
        set.Add(normalized);

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

    private void Cleanup(DateTime nowUtc)
    {
        var cutoff = nowUtc - _retention;
        while (_items.TryPeek(out var item) && item.TimestampUtc < cutoff)
        {
            _items.TryDequeue(out _);
        }
    }

    private sealed record CorrelationItem(string Domain, int ProcessId, string ProcessName, string ExecutablePath, DateTime TimestampUtc);
}

public sealed record CorrelationMatch(int ProcessId, string ProcessName, string ExecutablePath, DateTime TimestampUtc);
