using System.Diagnostics.Eventing.Reader;
using System.Text.RegularExpressions;
using Microsoft.Diagnostics.Tracing;

namespace DnsDefender.Collector.Parsing;

public static class DnsDomainExtractor
{
    private static readonly Regex DomainRegex = new(@"\b(?:(?:xn--)?[a-zA-Z0-9_](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?\.)+(?:xn--)?[a-zA-Z0-9_](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?\b", RegexOptions.Compiled);

    public static string? ExtractFromTraceEvent(TraceEvent data, params string[] preferredKeys)
    {
        foreach (var key in preferredKeys)
        {
            var value = GetPayloadValue(data, key);
            var normalized = NormalizeCandidate(value);
            if (normalized is not null)
            {
                return normalized;
            }
        }

        for (var i = 0; i < data.PayloadNames.Length; i++)
        {
            var normalized = NormalizeCandidate(data.PayloadValue(i)?.ToString());
            if (normalized is not null)
            {
                return normalized;
            }
        }

        return ExtractFromText(data.FormattedMessage);
    }

    public static string? ExtractFromOperational(string description, IList<EventProperty> properties)
    {
        var fromDescription = ExtractFromText(description);
        if (fromDescription is not null)
        {
            return fromDescription;
        }

        foreach (var property in properties)
        {
            var normalized = NormalizeCandidate(property.Value?.ToString());
            if (normalized is not null)
            {
                return normalized;
            }
        }

        return null;
    }

    public static string NormalizeDomain(string domain)
    {
        return domain.Trim().TrimEnd('.').ToLowerInvariant();
    }

    private static string? ExtractFromText(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return null;
        }

        var matches = DomainRegex.Matches(text);
        foreach (Match match in matches)
        {
            var normalized = NormalizeCandidate(match.Value);
            if (normalized is not null)
            {
                return normalized;
            }
        }

        return null;
    }

    private static string? NormalizeCandidate(string? candidate)
    {
        if (string.IsNullOrWhiteSpace(candidate))
        {
            return null;
        }

        var normalized = NormalizeDomain(candidate);
        if (IsValidDomain(normalized))
        {
            return normalized;
        }

        return ExtractDomainFromMixedString(candidate);
    }

    private static string? ExtractDomainFromMixedString(string text)
    {
        var matches = DomainRegex.Matches(text);
        foreach (Match match in matches)
        {
            var normalized = NormalizeDomain(match.Value);
            if (IsValidDomain(normalized))
            {
                return normalized;
            }
        }

        return null;
    }

    private static bool IsValidDomain(string normalized)
    {
        if (string.IsNullOrWhiteSpace(normalized) || !normalized.Contains('.'))
        {
            return false;
        }

        if (normalized == "null" || normalized == "localhost")
        {
            return false;
        }

        if (System.Net.IPAddress.TryParse(normalized, out _))
        {
            return false;
        }

        return DomainRegex.IsMatch(normalized);
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
}
