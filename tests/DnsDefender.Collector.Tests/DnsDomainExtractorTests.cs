using System.Diagnostics.Eventing.Reader;
using DnsDefender.Collector.Parsing;

namespace DnsDefender.Collector.Tests;

public class DnsDomainExtractorTests
{
    [Theory]
    [InlineData("_dns.resolver.arpa", "_dns.resolver.arpa")]
    [InlineData("_443._https.example.com", "_443._https.example.com")]
    [InlineData("Api.Example.COM.", "api.example.com")]
    [InlineData("xn--fiqs8s.xn--fiqz9s", "xn--fiqs8s.xn--fiqz9s")]
    public void NormalizeDomain_HandlesModernAndStandardNames(string input, string expected)
    {
        var normalized = DnsDomainExtractor.NormalizeDomain(input);
        Assert.Equal(expected, normalized);
    }

    [Fact]
    public void ExtractFromOperational_PicksDomainFromDescriptionWithServiceLabel()
    {
        var description = "queryName _443._https.example.com completed";
        var result = DnsDomainExtractor.ExtractFromOperational(description, Array.Empty<EventProperty>());
        Assert.Equal("_443._https.example.com", result);
    }

    [Fact]
    public void ExtractFromOperational_ReturnsNullForLocalhostAndIp()
    {
        var description = "lookup localhost and 127.0.0.1";
        var result = DnsDomainExtractor.ExtractFromOperational(description, Array.Empty<EventProperty>());
        Assert.Null(result);
    }
}
