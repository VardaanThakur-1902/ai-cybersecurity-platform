import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Legend,
} from "recharts";

interface ThreatChartsProps {
  threatLevels: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };

  networkAttacks: {
    attack_type: string;
    count: number;
  }[];
}

export default function ThreatCharts({
  threatLevels,
  networkAttacks,
}: ThreatChartsProps) {

  const threatData = [
    {
      name: "Critical",
      count: threatLevels.critical,
    },
    {
      name: "High",
      count: threatLevels.high,
    },
    {
      name: "Medium",
      count: threatLevels.medium,
    },
    {
      name: "Low",
      count: threatLevels.low,
    },
  ];

  return (
    <div className="charts-grid">

      {/* Threat Level Chart */}

      <div className="panel chart-panel">
        <h2>Threat Levels</h2>

        <ResponsiveContainer width="100%" height={300}>
          <BarChart data={threatData}>
            <CartesianGrid strokeDasharray="3 3" />

            <XAxis dataKey="name" />

            <YAxis allowDecimals={false} />

            <Tooltip />

            <Bar
              dataKey="count"
              name="Threats"
            />
          </BarChart>
        </ResponsiveContainer>
      </div>

      {/* Network Attack Chart */}

      <div className="panel chart-panel">
        <h2>Network Attack Distribution</h2>

        {networkAttacks.length === 0 ? (
          <div className="empty-state">
            No network attacks detected.
          </div>
        ) : (
          <ResponsiveContainer width="100%" height={300}>
            <PieChart>

              <Pie
                data={networkAttacks}
                dataKey="count"
                nameKey="attack_type"
                cx="50%"
                cy="50%"
                outerRadius={100}
                label
              >
                {networkAttacks.map((_, index) => (
                  <Cell key={index} />
                ))}
              </Pie>

              <Tooltip />

              <Legend />

            </PieChart>
          </ResponsiveContainer>
        )}

      </div>

    </div>
  );
}