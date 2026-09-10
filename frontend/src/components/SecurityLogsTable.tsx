import { useEffect, useState } from "react";

interface SecurityEvent {
  id: number;
  timestamp: string;
  source_ip: string;
  destination_ip: string | null;
  source_port: number | null;
  destination_port: number | null;
  protocol: string | null;
  event_type: string;
  severity: string;
  message: string;
  threat_score: number;
  threat_level: string;
  threat_type: string;
  detection_reasons: string | null;
}

interface LogsResponse {
  items: SecurityEvent[];
  total: number;
  skip: number;
  limit: number;
}

const API_BASE_URL = "http://127.0.0.1:8000";

export default function SecurityLogsTable() {
  const [logs, setLogs] = useState<SecurityEvent[]>([]);
  const [total, setTotal] = useState(0);

  const [loading, setLoading] = useState(true);

  const [threatLevel, setThreatLevel] = useState("");
  const [threatType, setThreatType] = useState("");
  const [sourceIp, setSourceIp] = useState("");

  const [page, setPage] = useState(0);

  const limit = 10;

  async function loadLogs() {
    setLoading(true);

    try {
      const params = new URLSearchParams();

      params.append("skip", String(page * limit));
      params.append("limit", String(limit));

      if (threatLevel) {
        params.append("threat_level", threatLevel);
      }

      if (threatType) {
        params.append("threat_type", threatType);
      }

      if (sourceIp) {
        params.append("source_ip", sourceIp);
      }

      const response = await fetch(
        `${API_BASE_URL}/logs/?${params.toString()}`
      );

      if (!response.ok) {
        throw new Error("Failed to fetch security logs");
      }

      const result: LogsResponse | SecurityEvent[] =
        await response.json();

      if (Array.isArray(result)) {
        setLogs(result);
        setTotal(result.length);
      } else {
        setLogs(result.items);
        setTotal(result.total);
      }
    } catch (error) {
      console.error("Failed to load security logs:", error);
      setLogs([]);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadLogs();

    const interval = setInterval(
        loadLogs,
        10000
    );

    return () => {
        clearInterval(interval);
    };
    }, [
    page,
    threatLevel,
    threatType,
    sourceIp
    ]);

  function applyFilters() {
    setPage(0);
    loadLogs();
  }

  function clearFilters() {
    setThreatLevel("");
    setThreatType("");
    setSourceIp("");
    setPage(0);
  }

  function getThreatClass(level: string) {
    return level.toLowerCase();
  }

  const totalPages = Math.ceil(total / limit);

  return (
    <div className="panel logs-panel">

      <div className="panel-header">
        <div>
          <h2>Security Logs</h2>
          <p>
            Security events detected by the platform
          </p>
        </div>

        <span className="flow-count">
          {total} events
        </span>
      </div>

      {/* Filters */}

      <div className="filters">

        <select
          value={threatLevel}
          onChange={(e) =>
            setThreatLevel(e.target.value)
          }
        >
          <option value="">
            All Threat Levels
          </option>

          <option value="critical">
            Critical
          </option>

          <option value="high">
            High
          </option>

          <option value="medium">
            Medium
          </option>

          <option value="low">
            Low
          </option>
        </select>

        <input
          type="text"
          placeholder="Source IP"
          value={sourceIp}
          onChange={(e) =>
            setSourceIp(e.target.value)
          }
        />

        <input
          type="text"
          placeholder="Threat Type"
          value={threatType}
          onChange={(e) =>
            setThreatType(e.target.value)
          }
        />

        <button
          className="filter-button"
          onClick={applyFilters}
        >
          Filter
        </button>

        <button
          className="clear-button"
          onClick={clearFilters}
        >
          Clear
        </button>

      </div>

      {/* Table */}

      {loading ? (
        <div className="empty-state">
          Loading security logs...
        </div>
      ) : logs.length === 0 ? (
        <div className="empty-state">
          No security events found.
        </div>
      ) : (
        <div className="table-container">

          <table className="flows-table">

            <thead>
              <tr>
                <th>Time</th>
                <th>Source IP</th>
                <th>Event Type</th>
                <th>Protocol</th>
                <th>Severity</th>
                <th>Threat Type</th>
                <th>Score</th>
                <th>Level</th>
                <th>Message</th>
              </tr>
            </thead>

            <tbody>

              {logs.map((log) => (

                <tr key={log.id}>

                  <td>
                    {new Date(
                      log.timestamp
                    ).toLocaleString()}
                  </td>

                  <td className="ip-address">
                    {log.source_ip}
                  </td>

                  <td>
                    {log.event_type}
                  </td>

                  <td>
                    {log.protocol ?? "N/A"}
                  </td>

                  <td>
                    {log.severity}
                  </td>

                  <td>
                    {log.threat_type}
                  </td>

                  <td>
                    <strong>
                      {log.threat_score}
                    </strong>
                  </td>

                  <td>
                    <span
                      className={`threat-badge ${getThreatClass(
                        log.threat_level
                      )}`}
                    >
                      {log.threat_level}
                    </span>
                  </td>

                  <td>
                    {log.message}
                  </td>

                </tr>

              ))}

            </tbody>

          </table>

        </div>
      )}

      {/* Pagination */}

      {totalPages > 1 && (
        <div className="pagination">

          <button
            disabled={page === 0}
            onClick={() =>
              setPage((current) =>
                Math.max(current - 1, 0)
              )
            }
          >
            ← Previous
          </button>

          <span>
            Page {page + 1} of {totalPages}
          </span>

          <button
            disabled={page >= totalPages - 1}
            onClick={() =>
              setPage((current) =>
                Math.min(
                  current + 1,
                  totalPages - 1
                )
              )
            }
          >
            Next →
          </button>

        </div>
      )}

    </div>
  );
}