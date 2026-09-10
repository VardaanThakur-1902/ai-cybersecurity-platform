import { useEffect, useState } from "react";

interface Alert {
  id: number;
  event_id: number | null;
  source_ip: string;
  threat_type: string;
  threat_level: string;
  threat_score: number;
  message: string;
  is_acknowledged: boolean;
  created_at: string;
}

const API_BASE_URL = "http://127.0.0.1:8000";

export default function AlertsPanel() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);

  async function loadAlerts() {
    try {
      const response = await fetch(
        `${API_BASE_URL}/alerts/?limit=10`
      );

      if (!response.ok) {
        throw new Error("Failed to fetch alerts");
      }

      const result = await response.json();

      setAlerts(result.items ?? result);
    } catch (error) {
      console.error("Failed to load alerts:", error);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadAlerts();

    const interval = setInterval(
        loadAlerts,
        10000
    );

    return () => {
        clearInterval(interval);
    };
    }, []);

  async function acknowledgeAlert(alertId: number) {
    try {
      const response = await fetch(
        `${API_BASE_URL}/alerts/${alertId}/acknowledge`,
        {
          method: "PATCH",
        }
      );

      if (!response.ok) {
        throw new Error("Failed to acknowledge alert");
      }

      await loadAlerts();
    } catch (error) {
      console.error("Failed to acknowledge alert:", error);
    }
  }

  function getThreatClass(level: string) {
    return level.toLowerCase();
  }

  if (loading) {
    return (
      <div className="panel">
        <h2>Security Alerts</h2>
        <div className="empty-state">
          Loading alerts...
        </div>
      </div>
    );
  }

  return (
    <div className="panel alerts-panel">

      <div className="panel-header">
        <div>
          <h2>Security Alerts</h2>
          <p>Recent detected security threats</p>
        </div>

        <span className="alert-count">
          {alerts.filter((alert) => !alert.is_acknowledged).length} active
        </span>
      </div>

      {alerts.length === 0 ? (
        <div className="empty-state">
          No security alerts detected.
        </div>
      ) : (
        <div className="alerts-list">

          {alerts.map((alert) => (
            <div
              key={alert.id}
              className={`alert-item ${
                alert.is_acknowledged ? "acknowledged" : ""
              }`}
            >

              <div className="alert-icon">
                {alert.is_acknowledged ? "✓" : "🚨"}
              </div>

              <div className="alert-content">

                <div className="alert-top">

                  <span
                    className={`threat-badge ${getThreatClass(
                      alert.threat_level
                    )}`}
                  >
                    {alert.threat_level}
                  </span>

                  <span className="alert-type">
                    {alert.threat_type}
                  </span>

                </div>

                <p className="alert-message">
                  {alert.message}
                </p>

                <div className="alert-meta">
                  <span>
                    Source: {alert.source_ip}
                  </span>

                  <span>
                    Score: {alert.threat_score}
                  </span>

                  <span>
                    {new Date(
                      alert.created_at
                    ).toLocaleString()}
                  </span>
                </div>

              </div>

              {!alert.is_acknowledged && (
                <button
                  className="acknowledge-button"
                  onClick={() =>
                    acknowledgeAlert(alert.id)
                  }
                >
                  Acknowledge
                </button>
              )}

            </div>
          ))}

        </div>
      )}

    </div>
  );
}