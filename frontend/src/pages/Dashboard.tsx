import { useEffect, useState } from "react";
import StatCard from "../components/StatCard";
import { getDashboard } from "../services/api";
import ThreatCharts from "../components/ThreatCharts";
import AlertsPanel from "../components/AlertsPanel";
import NetworkFlowsTable from "../components/NetworkFlowsTable";
import SecurityLogsTable from "../components/SecurityLogsTable";

interface DashboardData {
  stats: {
    total_events: number;

    threat_levels: {
      critical: number;
      high: number;
      medium: number;
      low: number;
    };

    network_flows: {
      total: number;
      malicious: number;
    };

    alerts: {
      total: number;
      active: number;
      acknowledged: number;
    };
  };

  analytics: {
    top_attacking_ips: {
      source_ip: string;
      count: number;
    }[];

    attack_type_distribution: {
      threat_type: string;
      count: number;
    }[];

    network_attack_distribution: {
      attack_type: string;
      count: number;
    }[];

    threats_by_hour: {
      hour: number;
      count: number;
    }[];

    threats_by_day: {
      date: string;
      count: number;
    }[];
  };
}

export default function Dashboard() {
  const [data, setData] = useState<DashboardData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    async function loadDashboard() {
      try {
        const result = await getDashboard();

        setData(result);
        setError("");
      } catch (err) {
        setError(
          "Unable to connect to cybersecurity backend."
        );

        console.error(err);
      } finally {
        setLoading(false);
      }
    }

    loadDashboard();

    const interval = setInterval(
      loadDashboard,
      10000
    );

    return () => {
      clearInterval(interval);
    };
  }, []);

  if (loading) {
    return (
      <div className="dashboard">
        <div className="panel">
          <p>Loading security dashboard...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="dashboard">
        <div className="panel error-panel">
          <h2>Backend Connection Error</h2>
          <p>{error}</p>
          <p>
            Make sure the FastAPI server is running on port 8000.
          </p>
        </div>
      </div>
    );
  }

  if (!data) {
    return null;
  }

  return (
    <div className="dashboard">

      {/* Statistics */}

      <div className="stats-grid">

        <StatCard
          title="Total Events"
          value={data.stats.total_events}
          icon="📋"
        />

        <StatCard
          title="Critical Threats"
          value={data.stats.threat_levels.critical}
          icon="🔴"
        />

        <StatCard
          title="Active Alerts"
          value={data.stats.alerts.active}
          icon="🚨"
        />

        <StatCard
          title="Malicious Flows"
          value={data.stats.network_flows.malicious}
          icon="⚠️"
        />

      </div>

      {/* Additional statistics */}

      <div className="stats-grid">

        <StatCard
          title="Total Network Flows"
          value={data.stats.network_flows.total}
          icon="🌐"
        />

        <StatCard
          title="High Threats"
          value={data.stats.threat_levels.high}
          icon="🟠"
        />

        <StatCard
          title="Medium Threats"
          value={data.stats.threat_levels.medium}
          icon="🟡"
        />

        <StatCard
          title="Acknowledged Alerts"
          value={data.stats.alerts.acknowledged}
          icon="✅"
        />

      </div>

      {/* Threat Charts */}

        <ThreatCharts
        threatLevels={data.stats.threat_levels}
        networkAttacks={
            data.analytics.network_attack_distribution
        }
        />

      {/* Security Alerts */}

      <AlertsPanel />

      <NetworkFlowsTable />

      <SecurityLogsTable />

      {/* Analytics */}

      <div className="dashboard-grid">

        <div className="panel">
          <h2>Attack Distribution</h2>

          {data.analytics.network_attack_distribution.length === 0 ? (
            <p>No network attacks detected.</p>
          ) : (
            data.analytics.network_attack_distribution.map(
              (attack) => (
                <div
                  key={attack.attack_type}
                  className="analytics-row"
                >
                  <span>{attack.attack_type}</span>
                  <strong>{attack.count}</strong>
                </div>
              )
            )
          )}
        </div>

        <div className="panel">
          <h2>Top Attacking IPs</h2>

          {data.analytics.top_attacking_ips.length === 0 ? (
            <p>No attacking IPs recorded.</p>
          ) : (
            data.analytics.top_attacking_ips.map((ip) => (
              <div
                key={ip.source_ip}
                className="analytics-row"
              >
                <span>{ip.source_ip}</span>
                <strong>{ip.count}</strong>
              </div>
            ))
          )}
        </div>

      </div>

      {/* Threat Levels */}

      <div className="panel">
        <h2>Threat Level Summary</h2>

        <div className="threat-summary">

          <div>
            <span>Critical</span>
            <strong>{data.stats.threat_levels.critical}</strong>
          </div>

          <div>
            <span>High</span>
            <strong>{data.stats.threat_levels.high}</strong>
          </div>

          <div>
            <span>Medium</span>
            <strong>{data.stats.threat_levels.medium}</strong>
          </div>

          <div>
            <span>Low</span>
            <strong>{data.stats.threat_levels.low}</strong>
          </div>

        </div>
      </div>

    </div>
  );
}