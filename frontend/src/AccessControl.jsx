import { useEffect, useState } from "react";
import { ShieldCheck, ShieldAlert, FileCheck2, AlertTriangle } from "lucide-react";
import { API_BASE_URL, getAccessToken } from "./api";
import "./AccessControl.css";

export default function AccessControl() {
  const [organizations, setOrganizations] = useState([]);
  const [records, setRecords] = useState([]);
  const [selectedOrg, setSelectedOrg] = useState("");
  const [selectedRecord, setSelectedRecord] = useState("");
  
  const [evaluating, setEvaluating] = useState(false);
  const [decision, setDecision] = useState(null);
  const [error, setError] = useState("");
  const [auditLog, setAuditLog] = useState([]);

  useEffect(() => {
    async function loadData() {
      try {
        const token = getAccessToken();
        if (!token) {
          setError("You are not logged in.");
          return;
        }
        const headers = { Authorization: `Bearer ${token}` };

        const [orgRes, recRes, logRes] = await Promise.all([
          fetch(`${API_BASE_URL}/api/organizations`, { headers }),
          fetch(`${API_BASE_URL}/api/cti/advanced`, { headers }),
          fetch(`${API_BASE_URL}/api/audit-logs`, { headers })
        ]);

        const orgData = await orgRes.json();
        const recData = await recRes.json();
        const logData = await logRes.json();

        // Parse Organizations
        if (orgData.organizations) {
          setOrganizations(orgData.organizations);
        } else if (Array.isArray(orgData)) {
          setOrganizations(orgData);
        }

        // Parse Records
        if (recData.records) {
          setRecords(recData.records);
        } else if (Array.isArray(recData)) {
          setRecords(recData);
        }

        // Parse Audit Logs
        if (Array.isArray(logData)) {
          setAuditLog(logData);
        }

      } catch (err) {
        console.error("Load error:", err);
        setError(`Failed to load data: ${err.message}`);
      }
    }
    loadData();
  }, []);

  // This log will tell us if React has the data before rendering
  console.log("Data loaded -> Organizations:", organizations);
  console.log("Data loaded -> Records:", records);

  const handleEvaluate = async (e) => {
    e.preventDefault();
    if (!selectedOrg || !selectedRecord) return;

    setEvaluating(true);
    setError("");
    setDecision(null);

    try {
      const token = getAccessToken();
      if (!token) throw new Error("Not authenticated. Please log in again.");

      const orgId = parseInt(selectedOrg, 10);
      const recordId = parseInt(selectedRecord, 10);
      
      const res = await fetch(`${API_BASE_URL}/api/advanced-policies`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`
        },
        body: JSON.stringify({
          organization_id: orgId,
          record_id: recordId
        })
      });

      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.error || `Server error (HTTP ${res.status})`);
      }

      const decisionVal = (data.decision || "").toUpperCase();
      const isGranted = decisionVal === "ALLOW" || decisionVal === "GRANTED" || data.allowed === true;

      setDecision({
        granted: isGranted,
        reason: data.reason || (isGranted ? "Policy requirements met." : "Policy requirements not met."),
        details: data.policy || data.details || {},
        trust_score: data.trust_score,
        trust_level: data.trust_level,
        sensitivity: data.sensitivity,
        policy_string: data.policy_string,
        classification: data.classification,
        attributes: data.attributes,
        missing: data.missing,
        risk_level: data.risk_level,
        risk_score: data.risk_score,
      });

      const logRes = await fetch(`${API_BASE_URL}/api/audit-logs`, { headers: { Authorization: `Bearer ${token}` } });
      if (logRes.ok) {
        setAuditLog(await logRes.json());
      }

    } catch (err) {
      console.error("Evaluation failed:", err);
      setError(err.message);
    } finally {
      setEvaluating(false);
    }
  };

  return (
    <div className="ac-page">
      <div className="ac-header">
        <h2>Adaptive Access Control</h2>
        <p>Evaluate sharing policies based on organization trust, threat severity, and adaptive risk rules.</p>
      </div>

      <div className="ac-grid">
        <div className="ac-card">
          <div className="ac-panel-heading">
            <FileCheck2 size={20} />
            <h3>Policy Decision Engine</h3>
          </div>

          <form className="ac-form" onSubmit={handleEvaluate}>
            <label>
              Requesting Organization
              <select value={selectedOrg} onChange={e => setSelectedOrg(e.target.value)} required>
                <option value="">Select organization...</option>
                {organizations.map((o) => (
                  <option key={o.id} value={o.id}>
                    {o.name} ({o.sector})
                  </option>
                ))}
              </select>
            </label>

            <label>
              Requested Threat Record
              <select value={selectedRecord} onChange={e => setSelectedRecord(e.target.value)} required>
                <option value="">Select IOC...</option>
                {records.map((r) => (
                  <option key={r.id} value={r.id}>
                    {r.indicator_value} ({r.severity})
                  </option>
                ))}
              </select>
            </label>

            <button type="submit" className="ac-btn" disabled={evaluating || !selectedOrg || !selectedRecord}>
              {evaluating ? "Evaluating Rules..." : "Evaluate Access Request"}
            </button>
          </form>

          {error && <div className="ac-error" style={{ marginTop: '16px', color: '#c73754', fontSize: '13px' }}>{error}</div>}

          {decision && (
            <div className={`ac-decision ${decision.granted ? "granted" : "denied"}`}>
              <div className="ac-decision-header">
                {decision.granted ? <ShieldCheck size={28} /> : <ShieldAlert size={28} />}
                <h3>{decision.granted ? "ACCESS GRANTED" : "ACCESS DENIED"}</h3>
              </div>
              <p className="ac-reason">{decision.reason}</p>

              <div className="ac-details">
                <h4>Access Decision Context:</h4>
                <ul>
                  {decision.sensitivity && (
                    <li><strong>Sensitivity (FIPS 199):</strong> {decision.sensitivity}</li>
                  )}
                  {decision.policy_string && (
                    <li><strong>Required Policy (LSSS):</strong> <code>{decision.policy_string}</code></li>
                  )}
                  {decision.trust_score !== undefined && (
                    <li><strong>Trust:</strong> {decision.trust_score}/100 — {decision.trust_level}</li>
                  )}
                  {decision.attributes && decision.attributes.length > 0 && (
                    <li><strong>Org Attributes:</strong> <code>{decision.attributes.join(", ")}</code></li>
                  )}
                  {decision.missing && decision.missing.length > 0 && (
                    <li><strong>Missing:</strong> <code>{decision.missing.join(", ")}</code></li>
                  )}
                  {decision.risk_level && (
                    <li><strong>Risk Level:</strong> {decision.risk_level}{decision.risk_score != null ? ` (score: ${decision.risk_score})` : ""}</li>
                  )}
                  {decision.classification && decision.classification.length > 0 && (
                    <li><strong>Classification:</strong> {decision.classification.join("; ")}</li>
                  )}
                </ul>
              </div>
            </div>
          )}
        </div>

        <div className="ac-card">
          <div className="ac-panel-heading">
            <AlertTriangle size={20} />
            <h3>Security Audit Trail</h3>
          </div>
          <p className="ac-sub">Permanent log of authorization decisions stored in the database.</p>

          <div className="ac-audit-list">
            {auditLog.length === 0 ? (
              <div className="ac-empty">No access requests evaluated yet.</div>
            ) : (
              auditLog.map((log, i) => (
                <div key={i} className="ac-audit-item">
                  <div className="ac-audit-time">
                    {log.timestamp ? new Date(log.timestamp).toLocaleTimeString() : 'Unknown time'}
                  </div>
                  <div className="ac-audit-content">
                    <strong>{log.organization_name}</strong> requested <strong>{log.record_value}</strong>
                  </div>
                  <div className={`ac-audit-status ${log.decision.toLowerCase()}`}>
                    {log.decision}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
}