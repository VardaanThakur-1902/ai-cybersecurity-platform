import { NavLink } from "react-router-dom";

export default function Sidebar() {
  return (
    <aside className="sidebar">

      <div className="logo">
        🛡️ AI CyberGuard
        <span>Threat Detection</span>
      </div>

      <nav>

        <NavLink
          to="/"
          className="nav-item"
        >
          📊 Dashboard
        </NavLink>

        <NavLink
          to="/alerts"
          className="nav-item"
        >
          🚨 Alerts
        </NavLink>

        <NavLink
          to="/network-flows"
          className="nav-item"
        >
          🌐 Network Flows
        </NavLink>

        <NavLink
          to="/security-logs"
          className="nav-item"
        >
          📋 Security Logs
        </NavLink>

        <NavLink
          to="/ml-detection"
          className="nav-item"
        >
          🤖 ML Detection
        </NavLink>

      </nav>

    </aside>
  );
}