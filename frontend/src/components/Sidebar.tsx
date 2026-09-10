export default function Sidebar() {
  return (
    <aside className="sidebar">
      <div className="logo">
        🛡️ CyberGuard
      </div>

      <nav>
        <a className="nav-item active">
          📊 Dashboard
        </a>

        <a className="nav-item">
          🚨 Alerts
        </a>

        <a className="nav-item">
          🌐 Network Flows
        </a>

        <a className="nav-item">
          📋 Security Logs
        </a>

        <a className="nav-item">
          🤖 ML Detection
        </a>
      </nav>
    </aside>
  );
}