import React, { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import 'bootstrap/dist/css/bootstrap.min.css';
import { ShieldAlert, Activity, Terminal, ShieldCheck, RefreshCcw, Lock } from 'lucide-react';

function App() {
  const [token, setToken] = useState(localStorage.getItem('token') || null);
  const [loginData, setLoginData] = useState({ username: '', password: '' });
  const [alerts, setAlerts] = useState([]);
  const [urlInput, setUrlInput] = useState('');
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(false);

  // function for Handling Admin Login
  const handleLogin = async (e) => {
    e.preventDefault();
    try {
      const res = await axios.post('http://localhost:5000/api/login', loginData);
      setToken(res.data.token);
      localStorage.setItem('token', res.data.token);
    } catch (err) {
      alert("Login Failed! Only authorized MZAMBHANI admins can access logs.", err);
    }
  };

  // function for Handling Admin Logout
  const handleLogout = () => {
    setToken(null);
    localStorage.removeItem('token');
    setAlerts([]);
  };

  // function for fetchAlerts
  const fetchAlerts = useCallback(() => {
      if (!token) return;
      axios.get('http://localhost:5000/api/alerts', {
          headers: { 'Authorization': token }
      })
      .then(res => {
        setAlerts(res.data);
        setLoading(false);
      })
      .catch(err => {
        console.log("Restricted Access", err);
        setLoading(false);
      });
  }, [token]); // It only changes if the token changes

// 3. function for fetchScans
const fetchScans = useCallback(() => {
    axios.get('http://localhost:5000/api/scans')
      .then(res => setScans(res.data))
      .catch(err => console.error("Scan API Error:", err));
}, []); // This never changes
   
useEffect(() => {
    fetchScans();
    if (token) {
      fetchAlerts();
    }

    const interval = setInterval(() => {
      fetchScans();
      if (token) fetchAlerts();
    }, 30000);

    return () => clearInterval(interval);
}, [token, fetchAlerts, fetchScans]); 

  // function to handle the scan
  const handleScan = async (e) => {
    e.preventDefault();
    if (!urlInput) return;

    try {
      // We only send the URL; the Backend handles the VirusTotal logic
      await axios.post('http://localhost:5000/api/scans', { url: urlInput }); 
      setUrlInput('');
      fetchScans();
    } catch (err) {
      alert("Error scanning URL. Check console for details.", err);
    }
  };

  return (
    <div className="container-fluid bg-dark text-light min-vh-100 p-0 m-0 d-flex flex-column">
      {/* Navbar */}
      <nav className="navbar navbar-dark bg-black border-bottom border-secondary px-4 w-100">
        <span className="navbar-brand d-flex align-items-center fw-bold">
          <ShieldAlert className="text-danger me-2" size={28} />
          MZAMBHANI <span className="text-secondary ms-2 fw-light">| Security Operations Center</span>
        </span>
        {token && (
          <div className="d-flex gap-2">
            <button onClick={fetchAlerts} className="btn btn-outline-info btn-sm">
              <RefreshCcw size={16} className={loading ? "spin" : ""} /> Refresh 
            </button>
            <button onClick={handleLogout} className="btn btn-outline-secondary btn-sm">Logout</button>
          </div>
        )}
      </nav>

      <div className="p-4">
        {/* SECTION 1: ADMIN-ONLY DASHBOARD */}
        {token ? (
          <>
            <div className="row g-3 mb-4 text-center">
              {/* Card 1: Log Alerts */}
              <div className="col-md-4">
                <div className="card bg-black border-danger shadow-lg">
                  <div className="card-body">
                    <h6 className="text-danger font-monospace">BRUTE_FORCE_ALERTS</h6>
                    <h2 className="display-5 fw-bold">{alerts.length}</h2>
                  </div>
                </div>
              </div>

              {/* Card 2: URL Threats */}
              <div className="col-md-4">
                <div className="card bg-black border-warning shadow-lg">
                  <div className="card-body">
                    <h6 className="text-warning font-monospace">MALICIOUS_URLS_FOUND</h6>
                    <h2 className="display-5 fw-bold">
                      {scans.filter(s => s.malicious_count > 0).length}
                    </h2>
                  </div>
                </div>
              </div>

              {/* Card 3: System Health */}
              <div className="col-md-4">
                <div className="card bg-black border-success shadow-lg">
                  <div className="card-body">
                    <h6 className="text-success font-monospace">MONITOR_STATUS</h6>
                    <h2 className="display-5 fw-bold text-success small mt-2">ACTIVE</h2>
                  </div>
                </div>
              </div>
            </div>

            {/* Alerts Table */}
            <div className="card bg-black border-secondary shadow mb-5">
              <div className="card-header border-secondary bg-dark text-info font-monospace text-center">
                [ LIVE_THREAT_FEED ]
              </div>
              <div className="card-body p-0">
                <div className="table-responsive">
                  <table className="table table-dark table-hover mb-0">
                    <thead className="table-secondary">
                      <tr className="text-secondary small"> 
                        <th>TIMESTAMP</th>
                        <th>SOURCE_IP</th>
                        <th>THREAT_TYPE</th>
                        <th>ATTEMPTS</th>
                        <th>SEVERITY</th>
                      </tr>
                    </thead>
                    <tbody>
                      {alerts.length === 0 ? (
                        <tr><td colSpan="5" className="text-center py-5 text-secondary font-monospace">NO THREATS DETECTED IN LOGS</td></tr>
                      ) : (
                        alerts.map((alert, index) => (
                          <tr key={index} className="font-monospace">
                            <td className="text-warning-emphasis small">{alert.timestamp}</td>
                            <td className="text-info fw-bold">{alert.ip}</td>
                            <td>{alert.type}</td>
                            <td>{alert.attempts}</td>
                            <td>
                              <span className={`badge ${alert.severity === 'High' ? 'bg-danger' : 'bg-warning'} text-black`}>
                                {alert.severity}
                              </span>
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          </>
        ) : (
          /* SHOW LOGIN PROMPT IF NO TOKEN */
          <div className="alert bg-black border-secondary text-center py-4 mb-5">
            <Lock className="text-secondary mb-2" size={32} />
            <h5 className="text-secondary">Admin</h5>
            <p className="small text-muted mb-3">Only Admins allowed. Unauthorized access prohibited.</p>
            <form onSubmit={handleLogin} className="d-flex justify-content-center gap-2 max-width-login mx-auto">
              <input 
                type="text" 
                className="form-control form-control-sm bg-dark text-white border-secondary w-25" 
                placeholder="Admin User"
                onChange={(e) => setLoginData({...loginData, username: e.target.value})}
              />
              <input 
                type="password" 
                className="form-control form-control-sm bg-dark text-white border-secondary w-25" 
                placeholder="Password"
                onChange={(e) => setLoginData({...loginData, password: e.target.value})}
              />
              <button type="submit" className="btn btn-sm btn-danger px-4">Unlock Admin Panel</button>
            </form>
          </div>
        )}

        {/* SECTION 2: PUBLIC PHISH-TANK */}
        <div className="card bg-black border-info mb-4 shadow text-center">
          <div className="card-header bg-info text-black fw-bold">🛡️ PHISH-TANK: URL INVESTIGATOR</div>
          <div className="card-body">
            <form onSubmit={handleScan} className="d-flex gap-2">
              <input 
                type="text" 
                className="form-control bg-dark text-white border-secondary" 
                placeholder="Enter URL to scan (e.g., https://malicious-site.com)"
                value={urlInput}
                onChange={(e) => setUrlInput(e.target.value)}
              />
              <button type="submit" className="btn btn-info">Analyze Link</button>
            </form>
          </div>
        </div>

        {/* URL SCAN HISTORY SECTION */}
        <div className="card bg-black border-info mb-5 shadow text-center">
          <div className="card-header border-info bg-dark text-info font-monospace">
            [ URL_SCAN_HISTORY ]
          </div>
          <div className="card-body p-0">
            <div className="table-responsive">
              <table className="table table-dark table-sm mb-0">
                <thead className="table-secondary">
                  <tr className="text-secondary small">
                    <th>URL_INVESTIGATED</th>
                    <th>ENGINES_FLAGGED</th>
                    <th>STATUS</th>
                    <th>SCAN_DATE</th>
                  </tr>
                </thead>
                <tbody>
                  {scans.length === 0 ? (
                    <tr><td colSpan="4" className="text-center py-3 text-muted">No URLs investigated yet.</td></tr>
                  ) : (
                    scans.map((scan, index) => (
                      <tr key={index} className="font-monospace">
                        <td className="text-truncate" style={{maxWidth: '300px'}}>{scan.url}</td>
                        <td className={scan.malicious_count > 0 ? "text-danger" : "text-success"}>
                          {scan.malicious_count} / {scan.total_engines}
                        </td>
                        <td>
                          {scan.malicious_count > 0 ? (
                            <span className="badge bg-danger">MALICIOUS</span>
                          ) : (
                            <span className="badge bg-success">CLEAN</span>
                          )}
                        </td>
                        <td className="text-info-emphasis small">{scan.scan_date}</td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>

      <style>{`
        .spin { animation: rotation 2s infinite linear; }
        @keyframes rotation { from { transform: rotate(0deg); } to { transform: rotate(359deg); } }
        .font-monospace { font-family: 'Courier New', Courier, monospace; }
        .max-width-login { max-width: 600px; }
      `}</style>
    </div>
  );
}

export default App;