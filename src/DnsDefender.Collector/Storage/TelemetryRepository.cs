using Microsoft.Data.Sqlite;
using DnsDefender.Common.Models;

namespace DnsDefender.Collector.Storage;

public sealed class TelemetryRepository
{
    private readonly string _connectionString;

    public TelemetryRepository(string databasePath)
    {
        _connectionString = $"Data Source={databasePath}";
    }

    public void Initialize()
    {
        using var connection = new SqliteConnection(_connectionString);
        connection.Open();

        using var command = connection.CreateCommand();
        command.CommandText = """
            CREATE TABLE IF NOT EXISTS dns_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp_utc TEXT NOT NULL,
                domain TEXT NOT NULL,
                query_type TEXT NOT NULL,
                response_code TEXT NOT NULL,
                returned_ips TEXT NOT NULL,
                process_id INTEGER NULL,
                process_name TEXT NOT NULL,
                executable_path TEXT NOT NULL,
                attribution_status INTEGER NOT NULL,
                attribution_confidence REAL NOT NULL,
                source TEXT NOT NULL,
                raw_summary TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_dns_domain ON dns_records(domain);
            CREATE INDEX IF NOT EXISTS idx_dns_time ON dns_records(timestamp_utc);
            CREATE INDEX IF NOT EXISTS idx_dns_pid ON dns_records(process_id);
            CREATE INDEX IF NOT EXISTS idx_dns_path ON dns_records(executable_path);
            """;
        command.ExecuteNonQuery();
    }

    public long Insert(DnsTelemetryRecord record)
    {
        using var connection = new SqliteConnection(_connectionString);
        connection.Open();

        using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO dns_records (
                timestamp_utc, domain, query_type, response_code, returned_ips,
                process_id, process_name, executable_path, attribution_status,
                attribution_confidence, source, raw_summary
            ) VALUES (
                $timestampUtc, $domain, $queryType, $responseCode, $returnedIps,
                $processId, $processName, $executablePath, $attributionStatus,
                $attributionConfidence, $source, $rawSummary
            );
            SELECT last_insert_rowid();
            """;

        command.Parameters.AddWithValue("$timestampUtc", record.TimestampUtc.ToString("O"));
        command.Parameters.AddWithValue("$domain", record.Domain);
        command.Parameters.AddWithValue("$queryType", record.QueryType);
        command.Parameters.AddWithValue("$responseCode", record.ResponseCode);
        command.Parameters.AddWithValue("$returnedIps", record.ReturnedIps);
        command.Parameters.AddWithValue("$processId", (object?)record.ProcessId ?? DBNull.Value);
        command.Parameters.AddWithValue("$processName", record.ProcessName);
        command.Parameters.AddWithValue("$executablePath", record.ExecutablePath);
        command.Parameters.AddWithValue("$attributionStatus", (int)record.AttributionStatus);
        command.Parameters.AddWithValue("$attributionConfidence", record.AttributionConfidence);
        command.Parameters.AddWithValue("$source", record.Source);
        command.Parameters.AddWithValue("$rawSummary", record.RawSummary);

        var inserted = command.ExecuteScalar();
        return inserted is long id ? id : 0;
    }

    public void ClearAll()
    {
        using var connection = new SqliteConnection(_connectionString);
        connection.Open();

        using var command = connection.CreateCommand();
        command.CommandText = "DELETE FROM dns_records;";
        command.ExecuteNonQuery();
    }

    public void UpdateAttributionById(long id, int processId, string processName, string executablePath, AttributionStatus attributionStatus, double attributionConfidence)
    {
        if (id <= 0)
        {
            return;
        }

        using var connection = new SqliteConnection(_connectionString);
        connection.Open();

        using var command = connection.CreateCommand();
        command.CommandText = """
            UPDATE dns_records
            SET process_id = $processId,
                process_name = $processName,
                executable_path = $executablePath,
                attribution_status = $attributionStatus,
                attribution_confidence = $attributionConfidence
            WHERE id = $id;
            """;

        command.Parameters.AddWithValue("$id", id);
        command.Parameters.AddWithValue("$processId", processId);
        command.Parameters.AddWithValue("$processName", processName ?? string.Empty);
        command.Parameters.AddWithValue("$executablePath", executablePath ?? string.Empty);
        command.Parameters.AddWithValue("$attributionStatus", (int)attributionStatus);
        command.Parameters.AddWithValue("$attributionConfidence", attributionConfidence);

        command.ExecuteNonQuery();
    }

    public IReadOnlyList<DnsTelemetryRecord> Search(string? domainKeyword, DateTime? fromUtc, DateTime? toUtc, int limit = 1000)
    {
        using var connection = new SqliteConnection(_connectionString);
        connection.Open();

        using var command = connection.CreateCommand();
        var where = new List<string>();

        if (!string.IsNullOrWhiteSpace(domainKeyword))
        {
            where.Add("domain LIKE $domain");
            command.Parameters.AddWithValue("$domain", $"%{domainKeyword.Trim().ToLowerInvariant()}%");
        }

        if (fromUtc.HasValue)
        {
            where.Add("timestamp_utc >= $fromUtc");
            command.Parameters.AddWithValue("$fromUtc", fromUtc.Value.ToString("O"));
        }

        if (toUtc.HasValue)
        {
            where.Add("timestamp_utc <= $toUtc");
            command.Parameters.AddWithValue("$toUtc", toUtc.Value.ToString("O"));
        }

        var whereClause = where.Count == 0 ? string.Empty : $"WHERE {string.Join(" AND ", where)}";

        command.CommandText = $"""
            SELECT id, timestamp_utc, domain, query_type, response_code, returned_ips,
                   process_id, process_name, executable_path, attribution_status,
                   attribution_confidence, source, raw_summary
            FROM dns_records
            {whereClause}
            ORDER BY id DESC
            LIMIT $limit;
            """;

        command.Parameters.AddWithValue("$limit", limit);

        using var reader = command.ExecuteReader();
        var result = new List<DnsTelemetryRecord>();

        while (reader.Read())
        {
            result.Add(new DnsTelemetryRecord
            {
                Id = reader.GetInt64(0),
                TimestampUtc = DateTime.Parse(reader.GetString(1)).ToUniversalTime(),
                Domain = reader.GetString(2),
                QueryType = reader.GetString(3),
                ResponseCode = reader.GetString(4),
                ReturnedIps = reader.GetString(5),
                ProcessId = reader.IsDBNull(6) ? null : reader.GetInt32(6),
                ProcessName = reader.GetString(7),
                ExecutablePath = reader.GetString(8),
                AttributionStatus = (AttributionStatus)reader.GetInt32(9),
                AttributionConfidence = reader.GetDouble(10),
                Source = reader.GetString(11),
                RawSummary = reader.GetString(12)
            });
        }

        return result;
    }
}
