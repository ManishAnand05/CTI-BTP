import { useEffect, useState, useMemo } from "react";
import { Crosshair, ShieldAlert, Cpu, Target } from "lucide-react";
import { API_BASE_URL, getAccessToken } from "./api";
import "./ATTACKNavigator.css";

const TACTIC_MAP = {
  "Initial Access": ["T1078", "T1190", "T1133", "T1566", "T1189"],
  "Execution": ["T1059", "T1059.001", "T1059.003", "T1204", "T1047"],
  "Persistence": ["T1098", "T1136", "T1543", "T1547", "T1505"],
  "Privilege Escalation": ["T1548", "T1068", "T1055", "T1134"],
  "Defense Evasion": ["T1070", "T1070.001", "T1562", "T1562.001", "T1027", "T1218", "T1014"],
  "Credential Access": ["T1003", "T1110", "T1552", "T1555", "T1056"],
  "Discovery": ["T1016", "T1087", "T1082", "T1083", "T1057", "T1518", "T1518.001"],
  "Lateral Movement": ["T1210", "T1570", "T1563", "T1021"],
  "Collection": ["T1005", "T1039", "T1025", "T1074", "T1114"],
  "Command and Control": ["T1071", "T1132", "T1008", "T1105", "T1102"],
  "Exfiltration": ["T1041", "T1048", "T1567", "T1029", "T1030"],
  "Impact": ["T1485", "T1486", "T1489", "T1490", "T1491", "T1657"]
};

export default function ATTACKNavigator({ orgContext }) {
  const [data, setData] = useState(null);
  const [selectedOrg, setSelectedOrg] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    async function loadData() {
      try {
        const token = getAccessToken();
        const res = await fetch(`${API_BASE_URL}/api/attack/matrix`, {
          headers: { Authorization: `Bearer ${token}` }
        });
        if (!res.ok) throw new Error("Failed to load ATT&CK data");
        const json = await res.json();
        setData(json);
        
        if (orgContext?.name) {
          setSelectedOrg(orgContext.name);
        } else if (json.organizations.length > 0) {
          setSelectedOrg(json.organizations[0].name);
        }
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    }
    loadData();
  }, [orgContext]);

  const activeTechniques = useMemo(() => {
    if (!data || !selectedOrg) return new Set();
    return new Set(data.org_techniques[selectedOrg] || []);
  }, [data, selectedOrg]);

  const suggestions = useMemo(() => {
    if (!data || !selectedOrg) return [];
    return data.suggestions[selectedOrg] || [];
  }, [data, selectedOrg]);

  if (loading) return <div style={{ padding: '50px', color: 'white' }}>Loading ATT&CK Matrix...</div>;
  if (error) return <div style={{ padding: '50px', color: 'red' }}>{error}</div>;

  return (
    <div className="an-page">
      <div className="an-header">
        <div>
          <h2>{orgContext ? `${orgContext.name} — ATT&CK Matrix` : 'MITRE ATT&CK Heatmap'}</h2>
          <p>Visualize organizational coverage and AI-driven collaborative predictions.</p>
        </div>
        
        <div className="an-controls">
          <label>Target Organization:</label>
          <select value={selectedOrg} onChange={(e) => setSelectedOrg(e.target.value)}>
            {data.organizations.map(o => (
              <option key={o.id} value={o.name}>{o.name}</option>
            ))}
          </select>
        </div>
      </div>

      <div className="an-layout">
        <div className="an-matrix-container">
          <div className="an-grid">
            {Object.entries(TACTIC_MAP).map(([tactic, techniques]) => (
              <div key={tactic} className="an-tactic-col">
                <div className="an-tactic-header">{tactic}</div>
                <div className="an-tech-list">
                  {techniques.map(tech => {
                    const isActive = activeTechniques.has(tech);
                    const count = data.global_frequency[tech] || 0;
                    
                    let heatClass = "";
                    if (isActive) {
                      if (count >= 3) heatClass = "level-3";
                      else if (count === 2) heatClass = "level-2";
                      else heatClass = "level-1";
                    }

                    return (
                      <div 
                        key={tech} 
                        className={`an-tech-card ${isActive ? `active ${heatClass}` : 'inactive'}`}
                        title={`Seen by ${count} organization(s)`}
                      >
                        <span className="an-tech-id">{tech}</span>
                        {isActive && <div className="an-tech-count">{count}</div>}
                      </div>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="an-sidebar">
          <div className="an-card">
            <div className="an-card-header">
              <Cpu size={18} color="#10b981" />
              <h3>AI Collaborative Prediction</h3>
            </div>
            <p className="an-card-desc">
              By comparing <strong>{selectedOrg}</strong> against all other organizations globally, the AI predicts these unseen techniques:
            </p>
            <div className="an-suggestions">
              {suggestions.length === 0 ? (
                <p className="an-muted">Not enough overlapping data to generate predictions yet.</p>
              ) : (
                suggestions.map((s) => (
                  <div key={s.tech} className="an-suggestion-item">
                    <Target size={16} color="#10b981" />
                    <span className="an-suggestion-id">{s.tech}</span>
                    <span className="an-confidence">{s.confidence}% Match</span>
                  </div>
                ))
              )}
            </div>
          </div>

          <div className="an-card">
            <div className="an-card-header">
              <ShieldAlert size={18} color="#ef4444" />
              <h3>Coverage Profile</h3>
            </div>
            <div className="an-profile-stat">
              <span>Techniques seen:</span>
              <strong>{activeTechniques.size}</strong>
            </div>
            <div className="an-profile-stat">
              <span>Global Intelligence Pool:</span>
              <strong>{Object.keys(data.global_frequency).length} techniques</strong>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}