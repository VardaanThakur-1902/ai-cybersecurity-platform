import { useEffect, useState } from "react";

export default function Header() {
  const [time, setTime] = useState(new Date());

  useEffect(() => {
    const interval = setInterval(() => {
      setTime(new Date());
    }, 1000);

    return () => clearInterval(interval);
  }, []);

  return (
    <header className="header">

      <div>
        <h1>Security Dashboard</h1>

        <p>
          AI-Powered Cybersecurity Threat Detection
        </p>
      </div>

      <div className="header-status">

        <div className="status">
          <span className="status-dot"></span>
          Live Monitoring
        </div>

        <div className="current-time">
          {time.toLocaleTimeString()}
        </div>

      </div>

    </header>
  );
}