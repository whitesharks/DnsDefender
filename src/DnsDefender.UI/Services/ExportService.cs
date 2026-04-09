using System.IO;
using System.Text;
using System.Text.Json;
using DnsDefender.Common.Models;

namespace DnsDefender.UI.Services;

public sealed class ExportService
{
    public void ExportCsv(string path, IReadOnlyList<DnsTelemetryRecord> records)
    {
        var sb = new StringBuilder();
        sb.AppendLine("TimestampUtc,Domain,QueryType,ResponseCode,ReturnedIps,ProcessId,ProcessName,ExecutablePath,AttributionStatus,AttributionConfidence,Source,RawSummary");

        foreach (var record in records)
        {
            sb.AppendLine(string.Join(',',
                Escape(record.TimestampUtc.ToString("O")),
                Escape(record.Domain),
                Escape(record.QueryType),
                Escape(record.ResponseCode),
                Escape(record.ReturnedIps),
                Escape(record.ProcessId?.ToString() ?? string.Empty),
                Escape(record.ProcessName),
                Escape(record.ExecutablePath),
                Escape(record.AttributionStatusText),
                Escape(record.AttributionConfidence.ToString("0.###")),
                Escape(record.Source),
                Escape(record.RawSummary)));
        }

        File.WriteAllText(path, sb.ToString(), Encoding.UTF8);
    }

    public void ExportJson(string path, IReadOnlyList<DnsTelemetryRecord> records)
    {
        var json = JsonSerializer.Serialize(records, new JsonSerializerOptions
        {
            WriteIndented = true
        });

        File.WriteAllText(path, json, Encoding.UTF8);
    }

    private static string Escape(string input)
    {
        if (input.Contains('"') || input.Contains(',') || input.Contains('\n') || input.Contains('\r'))
        {
            return $"\"{input.Replace("\"", "\"\"")}\"";
        }

        return input;
    }
}
