import { useEffect, useState } from "react";
import { AlertTriangle, ShieldAlert, Clock, Activity, TrendingUp, RefreshCw } from "lucide-react";
import { API_BASE_URL, getAccessToken } from "./api";
import "./TemporalIntelligence.css";

export default function TemporalIntelligence({ orgContext }) {
  const [data, setData] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const fetchTemporal = async () => {
    setLoading(true);
    setError("");
    try {
      const token = getAccessToken();
      if (!token) throw new Error("Not authenticated");

      const url = orgContext
        ? `${API_BASE_URL}/api/intelligence/temporal?org_id=${orgContext.id}`
        : `${API_BASE_URL}/api/intelligence/temporal`;

      const res = await fetch(url, {
        headers: { Authorization: `Bearer ${token}` }
      });
      
      if (!res.ok) throw new Error(`Server error: ${res.status}`);
      
      const json = await res.json();
      setData(json.intelligence || []);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTemporal();
  }, [orgContext]);

  if (loading) return <div className="ti-state">Loading temporal intelligence...</div>;
  
  if (error) return (
    <div className="ti-error">
      <AlertTriangle size={24} />
      <p>{error}</p>
      <button className="ti-retry-btn" onClick={fetchTemporal}>
        <RefreshCw size={14} /> Retry
      </button>
    </div>
  );
  
  if (data.length === 0) return <div className="ti-state">No intelligence records found for this organization.</div>;

  return (
    <div className="ti-page">
      <div className="ti-header">
        <h2>{orgContext ? `${orgContext.name} — Risk Intelligence` : 'Temporal & Risk Intelligence'}</h2>
        <p>Track how threat indicators evolve over time and understand the explainable risk scores.</p>
      </div>

      <div className="ti-grid">
        {data.map((item) => (
          <div key={item.indicator_value} className="ti-card">
            <div className="ti-card-left">
              <div className="ti-ioc-header">
                <span className="ti-type">{item.category || "IOC"}</span>
                <h3>{item.indicator_value}</h3>
              </div>
              <div className="ti-risk-gauge">
                <svg viewBox="0 0 36 36" className="circular-chart">
                  <path className="circle-bg" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" />
                  <path className="circle" strokeDasharray={`${item.risk_score}, 100`} d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" />
                  <text x="18" y="20.35" className="percentage">{item.risk_score}</text>
                </svg>
                <div className="ti-risk-label">Risk Score</div>
              </div>
              <div className="ti-explanation">
                <h4><TrendingUp size={14} /> Explainable Risk</h4>
                <ul>{item.risk_explanation.map((exp, i) => <li key={i}>{exp}</li>)}</ul>
              </div>
              <div className="ti-sectors">
                <h4><ShieldAlert size={14} /> Targeted Sectors</h4>
                <div className="ti-sector-tags">
                  {item.sectors.length > 0 ? item.sectors.map(s => <span key={s}>{s}</span>) : <span>Unknown</span>}
                </div>
              </div>
            </div>

            <div className="ti-card-right">
              <h4><Clock size={16} /> Evidence Timeline</h4>
              <div className="ti-timeline">
                {item.timeline.map((event, i) => {
                  const formattedDate = event.date 
                    ? new Date(event.date).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' })
                    : "Date Unknown";
                  return (
                    <div key={i} className="ti-timeline-item">
                      <div className="ti-timeline-dot" />
                      <div className="ti-timeline-content">
                        <div className="ti-timeline-header">
                          <strong>{event.org}</strong>
                          <span className="ti-date">{formattedDate}</span>
                        </div>
                        <div className="ti-timeline-body">
                          Reported as <strong className={`ti-sev ${event.severity.toLowerCase()}`}>{event.severity}</strong>
                          {event.sector && <span className="ti-sector-badge">{event.sector}</span>}
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}