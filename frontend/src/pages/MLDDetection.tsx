import { useState } from "react";

const API_BASE_URL = "http://127.0.0.1:8000";

interface PredictionResult {
  ml_result?: {
    prediction: number;
    classification: string;
    attack_probability: number;
  };

  threat_result?: {
    threat_score: number;
    threat_level: string;
    threat_type: string;
    detection_reasons: string;
  };

  flow?: {
    id: number;
  };
}

export default function MLDetection() {
  const [form, setForm] = useState({
    source_ip: "",
    destination_ip: "",
    source_port: "0",
    destination_port: "0",
    protocol: "TCP",

    flow_duration: "0",
    total_fwd_packets: "0",
    total_backward_packets: "0",
    total_length_fwd_packets: "0",
    total_length_bwd_packets: "0",

    fwd_packet_length_max: "0",
    fwd_packet_length_min: "0",
    bwd_packet_length_max: "0",
    bwd_packet_length_min: "0",

    flow_bytes_per_second: "0",
    flow_packets_per_second: "0",

    fwd_iat_total: "0",
    bwd_iat_total: "0",

    fwd_psh_flags: "0",
    bwd_psh_flags: "0",
    syn_flag_count: "0",
    ack_flag_count: "0",
    urg_flag_count: "0",

    average_packet_size: "0",
    active_mean: "0",
    idle_mean: "0",
  });

  const [result, setResult] =
    useState<PredictionResult | null>(null);

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  function handleChange(
    event: React.ChangeEvent<
      HTMLInputElement | HTMLSelectElement
    >
  ) {
    const { name, value } = event.target;

    setForm((current) => ({
      ...current,
      [name]: value,
    }));
  }

  function loadDDoSTestSample() {
    setForm({
      source_ip: "192.168.10.50",
      destination_ip: "192.168.10.100",
      source_port: "80",
      destination_port: "80",
      protocol: "TCP",

      flow_duration: "100000",
      total_fwd_packets: "1000",
      total_backward_packets: "10",
      total_length_fwd_packets: "100000",
      total_length_bwd_packets: "1000",

      fwd_packet_length_max: "1500",
      fwd_packet_length_min: "40",
      bwd_packet_length_max: "1500",
      bwd_packet_length_min: "40",

      flow_bytes_per_second: "1000000",
      flow_packets_per_second: "10000",

      fwd_iat_total: "100",
      bwd_iat_total: "100",

      fwd_psh_flags: "0",
      bwd_psh_flags: "0",
      syn_flag_count: "1",
      ack_flag_count: "1",
      urg_flag_count: "0",

      average_packet_size: "1000",
      active_mean: "100",
      idle_mean: "0",
    });

    setResult(null);
    setError("");
  }

  async function handleSubmit(
    event: React.FormEvent
  ) {
    event.preventDefault();

    setLoading(true);
    setError("");
    setResult(null);

    try {
      const payload = {
        source_ip: form.source_ip,
        destination_ip: form.destination_ip,
        source_port: Number(form.source_port),
        destination_port: Number(
          form.destination_port
        ),
        protocol: form.protocol,

        flow_duration: Number(form.flow_duration),
        total_fwd_packets: Number(
          form.total_fwd_packets
        ),
        total_backward_packets: Number(
          form.total_backward_packets
        ),
        total_length_fwd_packets: Number(
          form.total_length_fwd_packets
        ),
        total_length_bwd_packets: Number(
          form.total_length_bwd_packets
        ),

        fwd_packet_length_max: Number(
          form.fwd_packet_length_max
        ),
        fwd_packet_length_min: Number(
          form.fwd_packet_length_min
        ),
        bwd_packet_length_max: Number(
          form.bwd_packet_length_max
        ),
        bwd_packet_length_min: Number(
          form.bwd_packet_length_min
        ),

        flow_bytes_per_second: Number(
          form.flow_bytes_per_second
        ),
        flow_packets_per_second: Number(
          form.flow_packets_per_second
        ),

        fwd_iat_total: Number(
          form.fwd_iat_total
        ),
        bwd_iat_total: Number(
          form.bwd_iat_total
        ),

        fwd_psh_flags: Number(
          form.fwd_psh_flags
        ),
        bwd_psh_flags: Number(
          form.bwd_psh_flags
        ),
        syn_flag_count: Number(
          form.syn_flag_count
        ),
        ack_flag_count: Number(
          form.ack_flag_count
        ),
        urg_flag_count: Number(
          form.urg_flag_count
        ),

        average_packet_size: Number(
          form.average_packet_size
        ),
        active_mean: Number(
          form.active_mean
        ),
        idle_mean: Number(
          form.idle_mean
        ),
      };

      const response = await fetch(
        `${API_BASE_URL}/network-flows/`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify(payload),
        }
      );

      if (!response.ok) {
        const message = await response.text();

        throw new Error(
          message || "Prediction failed"
        );
      }

      const data = await response.json();

      setResult(data);
    } catch (error) {
      console.error(error);

      setError(
        "Unable to perform ML prediction."
      );
    } finally {
      setLoading(false);
    }
  }

  function getThreatClass(level: string) {
    return level.toLowerCase();
  }

  return (
    <div className="page">

      <div className="panel">

        <h2>ML Threat Detection</h2>

        <p>
          Submit network-flow features to the
          CIC-IDS2017 threat detection model.
        </p>

      </div>

      <div className="demo-actions">
        <button
          type="button"
          className="demo-button"
          onClick={loadDDoSTestSample}
        >
          ⚡ Load DDoS Demo Sample
        </button>
      </div>

      <form
        className="panel ml-form"
        onSubmit={handleSubmit}
      >

        <h2>Network Flow Input</h2>

        {/* Network Information */}

        <div className="form-section">

          <h3>Network Information</h3>

          <div className="form-grid">

            <div className="form-group">
              <label>Source IP</label>

              <input
                name="source_ip"
                value={form.source_ip}
                onChange={handleChange}
                placeholder="192.168.1.10"
                required
              />
            </div>

            <div className="form-group">
              <label>Destination IP</label>

              <input
                name="destination_ip"
                value={form.destination_ip}
                onChange={handleChange}
                placeholder="10.0.0.1"
                required
              />
            </div>

            <div className="form-group">
              <label>Source Port</label>

              <input
                type="number"
                name="source_port"
                value={form.source_port}
                onChange={handleChange}
              />
            </div>

            <div className="form-group">
              <label>Destination Port</label>

              <input
                type="number"
                name="destination_port"
                value={form.destination_port}
                onChange={handleChange}
              />
            </div>

            <div className="form-group">
              <label>Protocol</label>

              <select
                name="protocol"
                value={form.protocol}
                onChange={handleChange}
              >
                <option value="TCP">TCP</option>
                <option value="UDP">UDP</option>
                <option value="ICMP">ICMP</option>
              </select>
            </div>

          </div>

        </div>

        {/* Packet Features */}

        <div className="form-section">

          <h3>Packet Features</h3>

          <div className="form-grid">

            <div className="form-group">
              <label>Flow Duration</label>

              <input
                type="number"
                name="flow_duration"
                value={form.flow_duration}
                onChange={handleChange}
              />
            </div>

            <div className="form-group">
              <label>Total Fwd Packets</label>

              <input
                type="number"
                name="total_fwd_packets"
                value={form.total_fwd_packets}
                onChange={handleChange}
              />
            </div>

            <div className="form-group">
              <label>Total Backward Packets</label>

              <input
                type="number"
                name="total_backward_packets"
                value={
                  form.total_backward_packets
                }
                onChange={handleChange}
              />
            </div>

            <div className="form-group">
              <label>Total Length Fwd Packets</label>

              <input
                type="number"
                name="total_length_fwd_packets"
                value={
                  form.total_length_fwd_packets
                }
                onChange={handleChange}
              />
            </div>

            <div className="form-group">
              <label>Total Length Bwd Packets</label>

              <input
                type="number"
                name="total_length_bwd_packets"
                value={
                  form.total_length_bwd_packets
                }
                onChange={handleChange}
              />
            </div>

            <div className="form-group">
              <label>Fwd Packet Length Max</label>

              <input
                type="number"
                name="fwd_packet_length_max"
                value={
                  form.fwd_packet_length_max
                }
                onChange={handleChange}
              />
            </div>

            <div className="form-group">
              <label>Fwd Packet Length Min</label>

              <input
                type="number"
                name="fwd_packet_length_min"
                value={
                  form.fwd_packet_length_min
                }
                onChange={handleChange}
              />
            </div>

            <div className="form-group">
              <label>Bwd Packet Length Max</label>

              <input
                type="number"
                name="bwd_packet_length_max"
                value={
                  form.bwd_packet_length_max
                }
                onChange={handleChange}
              />
            </div>

            <div className="form-group">
              <label>Bwd Packet Length Min</label>

              <input
                type="number"
                name="bwd_packet_length_min"
                value={
                  form.bwd_packet_length_min
                }
                onChange={handleChange}
              />
            </div>

          </div>

        </div>

        {/* Traffic Features */}

        <div className="form-section">

          <h3>Traffic Features</h3>

          <div className="form-grid">

            <div className="form-group">
              <label>Flow Bytes / Second</label>

              <input
                type="number"
                name="flow_bytes_per_second"
                value={
                  form.flow_bytes_per_second
                }
                onChange={handleChange}
              />
            </div>

            <div className="form-group">
              <label>Flow Packets / Second</label>

              <input
                type="number"
                name="flow_packets_per_second"
                value={
                  form.flow_packets_per_second
                }
                onChange={handleChange}
              />
            </div>

            <div className="form-group">
              <label>Fwd IAT Total</label>

              <input
                type="number"
                name="fwd_iat_total"
                value={form.fwd_iat_total}
                onChange={handleChange}
              />
            </div>

            <div className="form-group">
              <label>Bwd IAT Total</label>

              <input
                type="number"
                name="bwd_iat_total"
                value={form.bwd_iat_total}
                onChange={handleChange}
              />
            </div>

            <div className="form-group">
              <label>Average Packet Size</label>

              <input
                type="number"
                name="average_packet_size"
                value={
                  form.average_packet_size
                }
                onChange={handleChange}
              />
            </div>

          </div>

        </div>

        {/* Flags */}

        <div className="form-section">

          <h3>TCP / Traffic Flags</h3>

          <div className="form-grid">

            <div className="form-group">
              <label>Fwd PSH Flags</label>

              <input
                type="number"
                name="fwd_psh_flags"
                value={form.fwd_psh_flags}
                onChange={handleChange}
              />
            </div>

            <div className="form-group">
              <label>Bwd PSH Flags</label>

              <input
                type="number"
                name="bwd_psh_flags"
                value={form.bwd_psh_flags}
                onChange={handleChange}
              />
            </div>

            <div className="form-group">
              <label>SYN Flag Count</label>

              <input
                type="number"
                name="syn_flag_count"
                value={form.syn_flag_count}
                onChange={handleChange}
              />
            </div>

            <div className="form-group">
              <label>ACK Flag Count</label>

              <input
                type="number"
                name="ack_flag_count"
                value={form.ack_flag_count}
                onChange={handleChange}
              />
            </div>

            <div className="form-group">
              <label>URG Flag Count</label>

              <input
                type="number"
                name="urg_flag_count"
                value={form.urg_flag_count}
                onChange={handleChange}
              />
            </div>

            <div className="form-group">
              <label>Active Mean</label>

              <input
                type="number"
                name="active_mean"
                value={form.active_mean}
                onChange={handleChange}
              />
            </div>

            <div className="form-group">
              <label>Idle Mean</label>

              <input
                type="number"
                name="idle_mean"
                value={form.idle_mean}
                onChange={handleChange}
              />
            </div>

          </div>

        </div>

        <button
          type="submit"
          className="predict-button"
          disabled={loading}
        >
          {loading
            ? "Analyzing..."
            : "🔍 Analyze Network Flow"}
        </button>

      </form>

      {/* Error */}

      {error && (
        <div className="panel error-panel">
          <h2>Prediction Error</h2>
          <p>{error}</p>
        </div>
      )}

      {/* Result */}

      {result && (
        <div className="panel prediction-result">

          <h2>Detection Result</h2>

          {result.ml_result && (
            <div className="result-grid">

              <div className="result-card">
                <span>Classification</span>

                <strong>
                  {result.ml_result.classification}
                </strong>
              </div>

              <div className="result-card">
                <span>Attack Probability</span>

                <strong>
                  {(
                    result.ml_result.attack_probability *
                    100
                  ).toFixed(1)}
                  %
                </strong>
              </div>

              {result.threat_result && (
                <>
                  <div className="result-card">
                    <span>Threat Score</span>

                    <strong>
                      {result.threat_result.threat_score}
                    </strong>
                  </div>

                  <div className="result-card">
                    <span>Threat Level</span>

                    <strong
                      className={`threat-badge ${getThreatClass(
                        result.threat_result.threat_level
                      )}`}
                    >
                      {result.threat_result.threat_level}
                    </strong>
                  </div>
                </>
              )}

            </div>
          )}

          {result.threat_result && (
            <div className="detection-reasons">

              <h3>Detection Details</h3>

              <p>
                <strong>Threat Type:</strong>{" "}
                {result.threat_result.threat_type}
              </p>

              <p>
                <strong>Reason:</strong>{" "}
                {result.threat_result.detection_reasons}
              </p>

            </div>
          )}

        </div>
      )}

    </div>
  );
}