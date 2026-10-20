import { useState, useEffect } from "react";
import { Lock, Unlock, ShieldOff, ShieldCheck, Key, FileKey, Activity, Shield } from "lucide-react";
import { API_BASE_URL, getAccessToken } from "./api";
import "./CryptoSharing.css";

export default function CryptoSharing() {
  const [organizations, setOrganizations] = useState([]);
  const [selectedOrg, setSelectedOrg] = useState("");

  const [ciphertext, setCiphertext] = useState("");
  const [generatedPolicy, setGeneratedPolicy] = useState("");
  const [decryptedData, setDecryptedData] = useState(null);
  const [decryptMeta, setDecryptMeta] = useState(null);
  const [errorMsg, setErrorMsg] = useState("");

  const [policySector, setPolicySector] = useState("Finance");
  const [severity, setSeverity] = useState("critical");
  const [isRevoked, setIsRevoked] = useState(false);
  const [cryptoStatus, setCryptoStatus] = useState(null);
  const [trustInfo, setTrustInfo] = useState(null);

  useEffect(() => {
    async function loadData() {
      const token = getAccessToken();
      const headers = { Authorization: `Bearer ${token}` };

      const [orgRes, statusRes] = await Promise.all([
        fetch(`${API_BASE_URL}/api/organizations`, { headers }),
        fetch(`${API_BASE_URL}/api/crypto/status`, { headers }).catch(() => null)
      ]);

      const orgData = await orgRes.json();
      setOrganizations(orgData.organizations || []);

      if (statusRes && statusRes.ok) {
        setCryptoStatus(await statusRes.json());
      }
    }
    loadData();
  }, []);

  useEffect(() => {
    if (!selectedOrg) { setTrustInfo(null); return; }
    async function loadTrust() {
      const token = getAccessToken();
      const res = await fetch(`${API_BASE_URL}/api/trust/compute/${selectedOrg}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (res.ok) setTrustInfo(await res.json());
    }
    loadTrust();
  }, [selectedOrg]);

  const handleEncrypt = async () => {
    const token = getAccessToken();
    const dummyRecord = {
      id: 99,
      indicator_value: "198.51.100.99",
      category: "ransomware",
      severity: severity,
      description: "Simulated confidential threat intelligence report."
    };

    const res = await fetch(`${API_BASE_URL}/api/crypto/encrypt`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify({
        record: dummyRecord,
        policy: { sector: policySector, min_trust: severity === "critical" ? 80 : severity === "high" ? 80 : 50 },
        auto_policy: true
      })
    });
    const data = await res.json();
    setCiphertext(data.ciphertext);
    setGeneratedPolicy(data.generated_policy || "");
    setDecryptedData(null);
    setDecryptMeta(null);
    setErrorMsg("");
  };

  const handleDecrypt = async () => {
    if (!selectedOrg) return;
    const org = organizations.find(o => o.id === parseInt(selectedOrg));

    const token = getAccessToken();
    const res = await fetch(`${API_BASE_URL}/api/crypto/decrypt`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify({
        ciphertext,
        user_attributes: { id: org.id, sector: org.sector, trust_score: org.trust_score }
      })
    });

    const data = await res.json();
    if (res.ok && data.success) {
      setDecryptedData(data.data);
      setDecryptMeta({ trust_score: data.trust_score, policy: data.policy, encrypted_at: data.encrypted_at });
      setErrorMsg("");
    } else {
      setDecryptedData(null);
      setDecryptMeta(null);
      setErrorMsg(data.reason);
    }
  };

  const handleRevoke = async () => {
    if (!selectedOrg) return;
    const token = getAccessToken();
    await fetch(`${API_BASE_URL}/api/crypto/revoke`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify({ organization_id: parseInt(selectedOrg), action: isRevoked ? "restore" : "revoke" })
    });
    setIsRevoked(!isRevoked);
    setDecryptedData(null);
    setDecryptMeta(null);
    setErrorMsg("");
    // Refresh trust info after revocation change
    const trustRes = await fetch(`${API_BASE_URL}/api/trust/compute/${selectedOrg}`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    if (trustRes.ok) setTrustInfo(await trustRes.json());
  };

  return (
    <div className="crypto-page">
      <div className="crypto-header">
        <h2>Privacy-Preserving CTI Sharing (PR-RABE)</h2>
        <p>Encrypt threat intelligence using attribute-based policies with AES-256-GCM and HKDF key derivation.</p>
      </div>

      {cryptoStatus && (
        <div className="crypto-status-bar">
          <Shield size={16} />
          <span><strong>Engine:</strong> {cryptoStatus.engine}</span>
          <span><strong>Policy:</strong> {cryptoStatus.policy_type}</span>
          <span><strong>Revoked Orgs:</strong> {cryptoStatus.revoked_organizations}</span>
        </div>
      )}

      <div className="crypto-grid">
        {/* LEFT: Encryption */}
        <div className="crypto-card">
          <div className="crypto-panel-heading">
            <Lock size={20} />
            <h3>1. Encrypt & Share</h3>
          </div>

          <div className="crypto-form">
            <label>
              Record Severity
              <select value={severity} onChange={e => setSeverity(e.target.value)}>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </label>

            <label>
              Sector Restriction
              <select value={policySector} onChange={e => setPolicySector(e.target.value)}>
                <option value="All">All Sectors</option>
                <option value="Finance">Finance Only</option>
                <option value="Healthcare">Healthcare Only</option>
              </select>
            </label>

            <button className="crypto-btn primary" onClick={handleEncrypt}>
              <FileKey size={16} /> Encrypt with PR-RABE
            </button>
          </div>

          {generatedPolicy && (
            <div className="policy-box">
              <p><strong>Auto-Generated LSSS Policy:</strong></p>
              <code>{generatedPolicy}</code>
            </div>
          )}

          {ciphertext && (
            <div className="ciphertext-box">
              <p><strong>Encrypted Ciphertext (AES-256-GCM):</strong></p>
              <div className="ciphertext-value">{ciphertext.substring(0, 120)}...</div>
              <p className="ciphertext-meta">{ciphertext.length} bytes, base64-encoded</p>
            </div>
          )}
        </div>

        {/* RIGHT: Decryption & Revocation */}
        <div className="crypto-card">
          <div className="crypto-panel-heading">
            <Unlock size={20} />
            <h3>2. Decrypt & Revoke</h3>
          </div>

          <div className="crypto-form">
            <label>
              Requesting Organization
              <select value={selectedOrg} onChange={e => setSelectedOrg(e.target.value)}>
                <option value="">Select organization...</option>
                {organizations.map(o => (
                  <option key={o.id} value={o.id}>{o.name} ({o.sector})</option>
                ))}
              </select>
            </label>

            {trustInfo && (
              <div className="trust-info-box">
                <Activity size={16} />
                <span>
                  <strong>Dynamic Trust:</strong> {trustInfo.trust_score}/100 ({trustInfo.trust_level})
                </span>
                {trustInfo.components && trustInfo.components.sharing && (
                  <div className="trust-breakdown">
                    <small>Sharing: {trustInfo.components.sharing.submissions} submissions | Violations: {trustInfo.components.violations.count} | Reliability: {trustInfo.components.reliability.score}%</small>
                  </div>
                )}
              </div>
            )}

            <div className="crypto-actions">
              <button className="crypto-btn success" onClick={handleDecrypt} disabled={!ciphertext || !selectedOrg}>
                <Key size={16} /> Attempt Decryption
              </button>

              <button className={`crypto-btn ${isRevoked ? 'warning' : 'danger'}`} onClick={handleRevoke} disabled={!selectedOrg}>
                <ShieldOff size={16} /> {isRevoked ? "Restore Access (Remove from Revocation)" : "Revoke Keys (AGK Rotation)"}
              </button>
            </div>
          </div>

          {errorMsg && (
            <div className="crypto-error">
              <ShieldOff size={18} /> {errorMsg}
            </div>
          )}

          {decryptedData && (
            <div className="crypto-success">
              <div className="success-header">
                <ShieldCheck size={20} /> Access Granted
              </div>
              {decryptMeta && (
                <div className="decrypt-meta">
                  <small>Trust Score: {decryptMeta.trust_score} | Policy: {decryptMeta.policy} | Encrypted: {decryptMeta.encrypted_at}</small>
                </div>
              )}
              <pre>{JSON.stringify(decryptedData, null, 2)}</pre>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
