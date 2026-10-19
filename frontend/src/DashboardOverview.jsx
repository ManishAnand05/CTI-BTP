import { useEffect, useState } from "react";
import { ShieldAlert, TrendingUp, AlertOctagon, Activity, Database, Building2, Cpu } from "lucide-react";
import { API_BASE_URL, getAccessToken } from "./api";
import "./DashboardOverview.css";

export default function DashboardOverview({ records, organizations }) {
  const [topRisks, setTopRisks] = useState([]);
  const [contradictions, setContradictions] = useState([]);
  const [aiData, setAiData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadOverviewData() {
      try {
        const token = getAccessToken();
        const headers = { Authorization: `Bearer ${token}` };

        const [riskRes, conflictRes, aiRes] = await Promise.all([
          fetch(`${API_BASE_URL}/api/intelligence/temporal`, { headers }),
          fetch(`${API_BASE_URL}/api/graph/contradictions`, { headers }),
          fetch(`${API_BASE_URL}/api/ai/predict`, { headers })
        ]);

        if (riskRes.ok) {
          const riskJson = await riskRes.json();
          const sorted = (riskJson.intelligence || []).sort((a, b) => b.risk_score - a.risk_score);
          setTopRisks(sorted.slice(0, 3));
        }

        if (conflictRes.ok) {
          const conflictJson = await conflictRes.json();
          setContradictions(conflictJson.contradictions || []);
        }

        if (aiRes.ok) {
          setAiData(await aiRes.json());
        }
      } catch (err) {
        console.error("Failed to load advanced overview", err);
      } finally {
        setLoading(false);
      }
    }
    loadOverviewData();
  }, []);

  return (
    <div className="dash-page">
      {/* KPI STRIP */}
      <div className="dash-kpi-grid">
        <div className="dash-kpi">
          <Database size={20} className="kpi-icon" />
          <div><span>Total Records</span><strong>{records.length}</strong></div>
        </div>
        <div className="dash-kpi">
          <AlertOctagon size={20} className="kpi-icon danger" />
          <div><span>Active Contradictions</span><strong>{contradictions.length}</strong></div>
        </div>
        <div className="dash-kpi">
          <Building2 size={20} className="kpi-icon" />
          <div><span>Organizations</span><strong>{organizations.length}</strong></div>
        </div>
      </div>

      {/* AI PREDICTION PANEL */}
      <div className="dash-card" style={{ marginBottom: '24px', borderLeft: '4px solid #10b981', background: '#f0fdf4' }}>
        <div className="dash-card-header">
          <Cpu size={20} color="#10b981" />
          <h3 style={{ color: '#168568' }}>AI Threat Prediction (Machine Learning)</h3>
        </div>
        {aiData && aiData.status === "Success" ? (
          <div style={{ display: 'flex', gap: '40px', alignItems: 'center' }}>
            <div>
              <p style={{ margin: 0, color: '#77758e', fontSize: '12px', fontWeight: 600 }}>PREDICTED NEXT SEVERITY</p>
              <h2 style={{ margin: '4px 0 0 0', color: '#168568', fontSize: '32px' }}>{aiData.ai_predicted_severity}</h2>
            </div>
            <div style={{ borderLeft: '1px solid #bbf7d0', paddingLeft: '40px' }}>
              <p style={{ margin: 0, color: '#77758e', fontSize: '12px', fontWeight: 600 }}>MODEL CONFIDENCE</p>
              <h3 style={{ margin: '4px 0 0 0', color: '#292454', fontSize: '24px' }}>{aiData.model_accuracy}%</h3>
            </div>
            <div style={{ borderLeft: '1px solid #bbf7d0', paddingLeft: '40px' }}>
              <p style={{ margin: 0, color: '#77758e', fontSize: '12px', fontWeight: 600 }}>FEATURES USED</p>
              <p style={{ margin: '4px 0 0 0', color: '#45435f', fontSize: '13px' }}>{aiData.features_used?.join(', ')}</p>
            </div>
          </div>
        ) : (
          <p className="dash-loading">{aiData?.message || "Training AI Model..."}</p>
        )}
      </div>

      <div className="dash-split">
        {/* TOP HIGH-RISK THREATS */}
        <div className="dash-card">
          <div className="dash-card-header">
            <TrendingUp size={20} />
            <h3>Top High-Risk Indicators</h3>
          </div>
          {loading ? <p className="dash-loading">Analyzing risk...</p> : (
            <div className="risk-list">
              {topRisks.length === 0 && <p className="dash-empty">No risk data available.</p>}
              {topRisks.map((risk) => (
                <div key={risk.indicator_value} className="risk-item">
                  <div className="risk-item-header">
                    <span className="risk-ioc">{risk.indicator_value}</span>
                    <span className={`risk-score ${risk.risk_score >= 80 ? 'critical' : 'high'}`}>
                      {risk.risk_score}/100
                    </span>
                  </div>
                  <div className="risk-details">
                    <span>{risk.category}</span>
                    <span>Latest: {risk.timeline[risk.timeline.length - 1]?.severity.toUpperCase()}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* CONTRADICTIONS */}
        <div className="dash-card">
          <div className="dash-card-header">
            <ShieldAlert size={20} className="text-danger" />
            <h3>Organizations Disagreeing</h3>
          </div>
          {loading ? <p className="dash-loading">Checking for conflicts...</p> : (
            <div className="conflict-list">
              {contradictions.length === 0 && <p className="dash-empty">All organizations agree on severity.</p>}
              {contradictions.slice(0, 4).map((conflict, idx) => (
                <div key={idx} className="conflict-item">
                  <strong>{conflict.indicator_value}</strong>
                  <p>{conflict.reports}</p>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* RECENT RECORDS TABLE */}
      <div className="dash-card" style={{ marginTop: '24px' }}>
        <div className="dash-card-header">
          <Activity size={20} />
          <h3>Recent Threat Intelligence</h3>
        </div>
        <div className="table-wrapper" style={{ marginTop: '16px' }}>
          <table className="data-table">
            <thead><tr><th>Indicator</th><th>Category</th><th>Severity</th></tr></thead>
            <tbody>
              {records.slice(0, 5).map((r, i) => (
                <tr key={i}>
                  <td style={{ fontFamily: 'monospace', fontWeight: 600 }}>{r.indicator_value}</td>
                  <td>{r.category || 'N/A'}</td>
                  <td>
                    <span className={`badge badge-${r.severity === 'critical' ? 'critical' : r.severity === 'high' ? 'high' : 'neutral'}`}>
                      {r.severity || 'N/A'}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}