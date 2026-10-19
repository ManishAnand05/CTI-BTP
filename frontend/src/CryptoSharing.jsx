import { useState, useEffect } from "react";
import { Lock, Unlock, ShieldOff, ShieldCheck, Key, FileKey } from "lucide-react";
import { API_BASE_URL, getAccessToken } from "./api";
import "./CryptoSharing.css";

export default function CryptoSharing() {
  const [organizations, setOrganizations] = useState([]);
  const [selectedOrg, setSelectedOrg] = useState("");
  
  const [ciphertext, setCiphertext] = useState("");
  const [decryptedData, setDecryptedData] = useState(null);
  const [errorMsg, setErrorMsg] = useState("");
  
  const [policySector, setPolicySector] = useState("Finance");
  const [isRevoked, setIsRevoked] = useState(false);

  useEffect(() => {
    async function loadOrgs() {
      const token = getAccessToken();
      const res = await fetch(`${API_BASE_URL}/api/organizations`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      const data = await res.json();
      setOrganizations(data.organizations || []);
    }
    loadOrgs();
  }, []);

  const handleEncrypt = async () => {
    const token = getAccessToken();
    const dummyRecord = {
      id: 99,
      indicator_value: "198.51.100.99",
      category: "ransomware",
      severity: "critical",
      description: "Simulated confidential threat intelligence report."
    };

    const res = await fetch(`${API_BASE_URL}/api/crypto/encrypt`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify({
        record: dummyRecord,
        policy: { sector: policySector, min_trust: 50 }
      })
    });
    const data = await res.json();
    setCiphertext(data.ciphertext);
    setDecryptedData(null);
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
    if (res.ok) {
      setDecryptedData(data.data);
      setErrorMsg("");
    } else {
      setDecryptedData(null);
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
    setErrorMsg("");
  };

  return (
    <div className="crypto-page">
      <div className="crypto-header">
        <h2>Privacy-Preserving CTI Sharing (PR-RABE)</h2>
        <p>Encrypt threat intelligence using attribute-based policies and manage cryptographic revocation.</p>
      </div>

      <div className="crypto-grid">
        {/* LEFT: Encryption */}
        <div className="crypto-card">
          <div className="crypto-panel-heading">
            <Lock size={20} />
            <h3>1. Encrypt & Share</h3>
          </div>
          
          <div className="crypto-form">
            <label>
              Policy Attribute (Sector Restriction)
              <select value={policySector} onChange={e => setPolicySector(e.target.value)}>
                <option value="All">All Sectors</option>
                <option value="Finance">Finance Only</option>
                <option value="Healthcare">Healthcare Only</option>
              </select>
            </label>

            <button className="crypto-btn primary" onClick={handleEncrypt}>
              <FileKey size={16} /> Generate Ciphertext
            </button>
          </div>

          {ciphertext && (
            <div className="ciphertext-box">
              <p><strong>Encrypted Ciphertext:</strong></p>
              <div className="ciphertext-value">{ciphertext}</div>
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

            <div className="crypto-actions">
              <button className="crypto-btn success" onClick={handleDecrypt} disabled={!ciphertext || !selectedOrg}>
                <Key size={16} /> Attempt Decryption
              </button>
              
              <button className={`crypto-btn ${isRevoked ? 'warning' : 'danger'}`} onClick={handleRevoke} disabled={!selectedOrg}>
                <ShieldOff size={16} /> {isRevoked ? "Restore Access" : "Revoke Keys"}
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
              <pre>{JSON.stringify(decryptedData, null, 2)}</pre>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}