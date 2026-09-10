import {
  BrowserRouter,
  Routes,
  Route,
} from "react-router-dom";

import Sidebar from "./components/Sidebar";
import Header from "./components/Header";

import Dashboard from "./pages/Dashboard";
import Alerts from "./pages/Alerts";
import NetworkFlows from "./pages/NetworkFlows";
import SecurityLogs from "./pages/SecurityLogs";
import MLDetection from "./pages/MLDDetection";

function App() {
  return (
    <BrowserRouter>

      <div className="app">

        <Sidebar />

        <main className="main-content">

          <Header />

          <Routes>

            <Route
              path="/"
              element={<Dashboard />}
            />

            <Route
              path="/alerts"
              element={<Alerts />}
            />

            <Route
              path="/network-flows"
              element={<NetworkFlows />}
            />

            <Route
              path="/security-logs"
              element={<SecurityLogs />}
            />

            <Route
              path="/ml-detection"
              element={<MLDetection />}
            />

          </Routes>

        </main>

      </div>

    </BrowserRouter>
  );
}

export default App;