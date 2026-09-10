import { useEffect, useState } from "react";

interface NetworkFlow {
  id: number;
  source_ip: string;
  destination_ip: string;
  source_port: number | null;
  destination_port: number | null;
  protocol: string | null;

  ml_prediction: number | null;
  attack_probability: number | null;

  threat_score: number;
  threat_level: string;
  threat_type: string;
}

const API_BASE_URL = "http://127.0.0.1:8000";

export default function NetworkFlowsTable() {
  const [flows, setFlows] = useState<NetworkFlow[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadFlows() {
        try {
        const response = await fetch(
            `${API_BASE_URL}/network-flows/?limit=10`
        );

        if (!response.ok) {
            throw new Error(
            "Failed to fetch network flows"
            );
        }

        const result = await response.json();

        setFlows(result.items ?? result);
        } catch (error) {
        console.error(
            "Failed to load network flows:",
            error
        );
        } finally {
        setLoading(false);
        }
    }

    loadFlows();

    const interval = setInterval(
        loadFlows,
        10000
    );

    return () => {
        clearInterval(interval);
    };
    }, []);

  function getThreatClass(level: string) {
    return level.toLowerCase();
  }

  function formatProbability(
    probability: number | null
  ) {
    if (probability === null) {
      return "N/A";
    }

    return `${(probability * 100).toFixed(1)}%`;
  }

  if (loading) {
    return (
      <div className="panel">
        <h2>Network Flow Monitoring</h2>

        <div className="empty-state">
          Loading network flows...
        </div>
      </div>
    );
  }

  return (
    <div className="panel flows-panel">

      <div className="panel-header">
        <div>
          <h2>Network Flow Monitoring</h2>
          <p>
            ML-analyzed network traffic
          </p>
        </div>

        <span className="flow-count">
          {flows.length} flows
        </span>
      </div>

      {flows.length === 0 ? (
        <div className="empty-state">
          No network flows recorded.
        </div>
      ) : (
        <div className="table-container">

          <table className="flows-table">

            <thead>
              <tr>
                <th>Source IP</th>
                <th>Destination IP</th>
                <th>Protocol</th>
                <th>Destination Port</th>
                <th>Prediction</th>
                <th>Attack Probability</th>
                <th>Score</th>
                <th>Threat Level</th>
              </tr>
            </thead>

            <tbody>

              {flows.map((flow) => (

                <tr key={flow.id}>

                  <td className="ip-address">
                    {flow.source_ip}
                  </td>

                  <td className="ip-address">
                    {flow.destination_ip}
                  </td>

                  <td>
                    {flow.protocol ?? "N/A"}
                  </td>

                  <td>
                    {flow.destination_port ?? "N/A"}
                  </td>

                  <td>
                    {flow.ml_prediction === 1 ? (
                      <span className="prediction malicious">
                        MALICIOUS
                      </span>
                    ) : (
                      <span className="prediction benign">
                        BENIGN
                      </span>
                    )}
                  </td>

                  <td>
                    {formatProbability(
                      flow.attack_probability
                    )}
                  </td>

                  <td>
                    <strong>
                      {flow.threat_score}
                    </strong>
                  </td>

                  <td>
                    <span
                      className={`threat-badge ${getThreatClass(
                        flow.threat_level
                      )}`}
                    >
                      {flow.threat_level}
                    </span>
                  </td>

                </tr>

              ))}

            </tbody>

          </table>

        </div>
      )}

    </div>
  );
}