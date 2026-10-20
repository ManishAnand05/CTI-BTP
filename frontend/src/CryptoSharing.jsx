import { useState, useEffect } from "react";
import { Lock, Unlock, ShieldOff, ShieldCheck, Key, FileKey, Activity, Shield, Database, Eye } from "lucide-react";
import { API_BASE_URL, getAccessToken } from "./api";
import "./CryptoSharing.css";

export default function CryptoSharing() {
  const [userOrg, setUserOrg] = useState(null);
  const [ctiRecords, setCtiRecords] = useState([]);
  const [encryptedRecords, setEncryptedRecords] = useState([]);
  const [selectedRecord, setSelectedRecord] = useState("");
  const [selectedEncrypted, setSelectedEncrypted] = useState("");

  const [generatedPolicy, setGeneratedPolicy] = useState("");
  const [decryptedData, setDecryptedData] = useState(null);
  const [decryptMeta, setDecryptMeta] = useState(null);
  const [errorMsg, setErrorMsg] = useState("");
  const [encryptMsg, setEncryptMsg] = useState("");

  const [policySector, setPolicySector] = useState("Finance");
  const [isRevoked, setIsRevoked] = useState(false);
  const [cryptoStatus, setCryptoStatus] = useState(null);
  const [trustInfo, setTrustInfo] = useState(null);
  const [encryptMeta, setEncryptMeta] = useState(null);

  const token = getAccessToken();
  const headers = { Authorization: `Bearer ${token}` };
  const jsonHeaders = { "Content-Type": "application/json", Authorization: `Bearer ${token}` };

  async function loadEncryptedRecords() {
    try {
      const res = await fetch(`${API_BASE_URL}/api/crypto/encrypted`, { headers });
      if (res.ok) {
        const data = await res.json();
        setEncryptedRecords(data.records || []);
      }
    } catch { /* ignore */ }
  }

  useEffect(() => {
    async function loadData() {
      const [meRes, ctiRes, statusRes] = await Promise.all([
        fetch(`${API_BASE_URL}/api/auth/me`, { headers }),
        fetch(`${API_BASE_URL}/api/cti/advanced`, { headers }),
        fetch(`${API_BASE_URL}/api/crypto/status`, { headers }).catch(() => null),
      ]);

      if (meRes.ok) {
        const meData = await meRes.json();
        setUserOrg(meData.organization || null);
      }

      const ctiData = await ctiRes.json();
      setCtiRecords(ctiData.records || (Array.isArray(ctiData) ? ctiData : []));

      if (statusRes && statusRes.ok) {
        setCryptoStatus(await statusRes.json());
      }

      await loadEncryptedRecords();
    }
    loadData();
  }, []);

  useEffect(() => {
    if (!userOrg) { setTrustInfo(null); return; }
    async function loadTrust() {
      const res = await fetch(`${API_BASE_URL}/api/trust/compute/${userOrg.id}`, { headers });
      if (res.ok) setTrustInfo(await res.json());
    }
    loadTrust();
  }, [userOrg]);

  const selectedCTI = ctiRecords.find(r => r.id === parseInt(selectedRecord));
  const selectedEnc = encryptedRecords.find(r => r.id === parseInt(selectedEncrypted));

  const handleEncrypt = async () => {
    if (!selectedCTI) return;

    const fullRecord = {
      id: selectedCTI.id,
      title: selectedCTI.title,
      indicator_type: selectedCTI.indicator_type,
      indicator_value: selectedCTI.indicator_value,
      category: selectedCTI.category,
      severity: selectedCTI.severity,
      confidence: selectedCTI.confidence,
      risk_level: selectedCTI.risk_level,
      risk_score: selectedCTI.risk_score,
      description: selectedCTI.description,
      sharing_sector: selectedCTI.sharing_sector,
      stix_bundle: selectedCTI.stix_data ? (typeof selectedCTI.stix_data === "string" ? JSON.parse(selectedCTI.stix_data) : selectedCTI.stix_data) : null,
    };

    const res = await fetch(`${API_BASE_URL}/api/crypto/encrypt`, {
      method: "POST",
      headers: jsonHeaders,
      body: JSON.stringify({
        record: fullRecord,
        policy: { sector: policySector, min_trust: selectedCTI.severity === "critical" || selectedCTI.severity === "high" ? 80 : 50 },
        auto_policy: true,
      }),
    });
    const data = await res.json();
    setGeneratedPolicy(data.generated_policy || "");
    setEncryptMeta(data.sensitivity ? { sensitivity: data.sensitivity, classification: data.classification } : null);
    setEncryptMsg(`Encrypted and stored successfully. Policy: ${data.generated_policy || "default"}`);

    await loadEncryptedRecords();
  };

  const handleDecrypt = async () => {
    if (!selectedEnc) return;
    setDecryptedData(null);
    setDecryptMeta(null);
    setErrorMsg("");

    const res = await fetch(`${API_BASE_URL}/api/crypto/decrypt`, {
      method: "POST",
      headers: jsonHeaders,
      body: JSON.stringify({ encrypted_record_id: selectedEnc.id }),
    });

    const data = await res.json();
    if (res.ok && data.success) {
      setDecryptedData(data.data);
      setDecryptMeta({ trust_score: data.trust_score, policy: data.policy, encrypted_at: data.encrypted_at });
      setErrorMsg("");
    } else {
      setDecryptedData(null);
      setDecryptMeta(null);
      setErrorMsg(data.reason || "Access denied.");
    }
  };

  const handleRevoke = async () => {
    if (!userOrg) return;
    await fetch(`${API_BASE_URL}/api/crypto/revoke`, {
      method: "POST",
      headers: jsonHeaders,
      body: JSON.stringify({ organization_id: userOrg.id, action: isRevoked ? "restore" : "revoke" }),
    });
    setIsRevoked(!isRevoked);
    setDecryptedData(null);
    setDecryptMeta(null);
    setErrorMsg("");
    const [trustRes, statusRes] = await Promise.all([
      fetch(`${API_BASE_URL}/api/trust/compute/${userOrg.id}`, { headers }),
      fetch(`${API_BASE_URL}/api/crypto/status`, { headers }),
    ]);
    if (trustRes.ok) setTrustInfo(await trustRes.json());
    if (statusRes.ok) setCryptoStatus(await statusRes.json());
  };

  return (
    <div className="crypto-page">
      <div className="crypto-header">
        <h2>Privacy-Preserving CTI Sharing (PR-RABE)</h2>
        <p>Encrypt threat intelligence with attribute-based policies. Other organizations attempt decryption — access is granted or denied based on their trust level, sector, and revocation status.</p>
      </div>

      {cryptoStatus && (
        <div className="crypto-status-bar">
          <Shield size={16} />
          <span><strong>Engine:</strong> {cryptoStatus.engine}</span>
          <span><strong>Policy:</strong> {cryptoStatus.policy_type}</span>
          <span><strong>Revoked Orgs:</strong> {cryptoStatus.revoked_organizations}</span>
        </div>
      )}

      {userOrg && (
        <div className="crypto-status-bar" style={{ background: "rgba(56, 189, 248, 0.08)", borderColor: "rgba(56, 189, 248, 0.2)" }}>
          <Database size={16} />
          <span><strong>Logged in as:</strong> {userOrg.name} ({userOrg.sector})</span>
          <span><strong>Trust:</strong> {userOrg.trust_score}/100</span>
        </div>
      )}

      <div className="crypto-grid">
        {/* LEFT: Encryption */}
        <div className="crypto-card">
          <div className="crypto-panel-heading">
            <Lock size={20} />
            <h3>1. Encrypt & Publish CTI Record</h3>
          </div>

          <div className="crypto-form">
            <label>
              CTI Record to Encrypt
              <select value={selectedRecord} onChange={e => { setSelectedRecord(e.target.value); setEncryptMsg(""); setGeneratedPolicy(""); }}>
                <option value="">Select a threat record...</option>
                {ctiRecords.map(r => (
                  <option key={r.id} value={r.id}>
                    {r.title} ({r.severity}) — {r.sharing_sector}
                  </option>
                ))}
              </select>
            </label>

            {selectedCTI && (
              <div className="record-preview">
                <div className="record-preview-header">
                  <Eye size={14} />
                  <strong>Record Preview</strong>
                </div>
                <div className="record-preview-body">
                  <div><strong>Category:</strong> {selectedCTI.category}</div>
                  <div><strong>Indicator:</strong> <code>{selectedCTI.indicator_value}</code></div>
                  <div><strong>Severity:</strong> <span className={`sev-badge sev-${selectedCTI.severity}`}>{selectedCTI.severity}</span></div>
                  <div><strong>Risk:</strong> {selectedCTI.risk_level} ({selectedCTI.risk_score}/100)</div>
                  <div><strong>Sector:</strong> {selectedCTI.sharing_sector}</div>
                  <div className="record-preview-desc">{selectedCTI.description}</div>
                </div>
              </div>
            )}

            <label>
              Sector Restriction
              <select value={policySector} onChange={e => setPolicySector(e.target.value)}>
                <option value="All">All Sectors</option>
                <option value="Finance">Finance</option>
                <option value="Healthcare">Healthcare</option>
                <option value="Education">Education</option>
                <option value="Technology">Technology</option>
                <option value="Government">Government</option>
                <option value="Energy">Energy</option>
              </select>
            </label>

            <button className="crypto-btn primary" onClick={handleEncrypt} disabled={!selectedRecord}>
              <FileKey size={16} /> Encrypt with PR-RABE
            </button>
          </div>

          {encryptMsg && (
            <div className="policy-box">
              <p><strong>{encryptMsg}</strong></p>
              {generatedPolicy && (
                <div>
                  <p style={{ marginTop: "8px" }}><strong>LSSS Policy:</strong></p>
                  <code>{generatedPolicy}</code>
                </div>
              )}
              {encryptMeta && (
                <div style={{ marginTop: "8px", fontSize: "13px", color: "#8899aa" }}>
                  <strong>Sensitivity:</strong> {encryptMeta.sensitivity} &nbsp;|&nbsp;
                  <strong>Classification:</strong> {encryptMeta.classification.join("; ")}
                </div>
              )}
            </div>
          )}
        </div>

        {/* RIGHT: Decryption */}
        <div className="crypto-card">
          <div className="crypto-panel-heading">
            <Unlock size={20} />
            <h3>2. Decrypt Encrypted Record</h3>
          </div>

          <div className="crypto-form">
            {userOrg ? (
              <div className="org-auto-bound">
                <strong>Your Organization:</strong> {userOrg.name} ({userOrg.sector})
              </div>
            ) : (
              <div className="org-auto-bound" style={{ color: "#ef4444" }}>
                Loading your organization...
              </div>
            )}

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

            <label>
              Select Encrypted Record
              <select value={selectedEncrypted} onChange={e => { setSelectedEncrypted(e.target.value); setDecryptedData(null); setDecryptMeta(null); setErrorMsg(""); }}>
                <option value="">Choose an encrypted record to decrypt...</option>
                {encryptedRecords.map(r => (
                  <option key={r.id} value={r.id}>
                    {r.title} ({r.severity}) — Policy: {r.policy_display} — by {r.encrypted_by_org}
                  </option>
                ))}
              </select>
            </label>

            {selectedEnc && (
              <div className="record-preview" style={{ borderColor: "rgba(139, 92, 246, 0.3)", background: "rgba(139, 92, 246, 0.04)" }}>
                <div className="record-preview-header">
                  <Lock size={14} />
                  <strong>Encrypted Record Details</strong>
                </div>
                <div className="record-preview-body">
                  <div><strong>Original Title:</strong> {selectedEnc.title}</div>
                  <div><strong>Severity:</strong> <span className={`sev-badge sev-${selectedEnc.severity}`}>{selectedEnc.severity}</span></div>
                  <div><strong>Category:</strong> {selectedEnc.category}</div>
                  <div><strong>Sector:</strong> {selectedEnc.sharing_sector}</div>
                  <div><strong>Policy:</strong> <code>{selectedEnc.policy_display}</code></div>
                  {selectedEnc.sensitivity && <div><strong>Sensitivity:</strong> {selectedEnc.sensitivity}</div>}
                  <div><strong>Encrypted by:</strong> {selectedEnc.encrypted_by_org}</div>
                  <div><strong>Encrypted at:</strong> {new Date(selectedEnc.created_at).toLocaleString()}</div>
                </div>
              </div>
            )}

            <div className="crypto-actions">
              <button className="crypto-btn success" onClick={handleDecrypt} disabled={!selectedEnc || !userOrg}>
                <Key size={16} /> Attempt Decryption
              </button>

              <button className={`crypto-btn ${isRevoked ? "warning" : "danger"}`} onClick={handleRevoke} disabled={!userOrg}>
                <ShieldOff size={16} /> {isRevoked ? "Restore Access" : "Revoke Keys (AGK Rotation)"}
              </button>
            </div>
          </div>

          {errorMsg && (
            <div className="crypto-error">
              <ShieldOff size={18} /> <strong>Access Denied:</strong> {errorMsg}
            </div>
          )}

          {decryptedData && (
            <div className="crypto-success">
              <div className="success-header">
                <ShieldCheck size={20} /> Access Granted — Decrypted Intelligence
              </div>
              {decryptMeta && (
                <div className="decrypt-meta">
                  <small>Trust Score: {decryptMeta.trust_score} | Policy: {decryptMeta.policy} | Encrypted: {decryptMeta.encrypted_at}</small>
                </div>
              )}
              <div className="decrypted-intel">
                {decryptedData.title && <h4 className="intel-title">{decryptedData.title}</h4>}
                <div className="intel-grid">
                  {decryptedData.category && <div className="intel-field"><span className="intel-label">Category</span><span>{decryptedData.category}</span></div>}
                  {decryptedData.indicator_value && <div className="intel-field"><span className="intel-label">Indicator</span><code>{decryptedData.indicator_value}</code></div>}
                  {decryptedData.indicator_type && <div className="intel-field"><span className="intel-label">Type</span><span>{decryptedData.indicator_type}</span></div>}
                  {decryptedData.severity && <div className="intel-field"><span className="intel-label">Severity</span><span className={`sev-badge sev-${decryptedData.severity}`}>{decryptedData.severity}</span></div>}
                  {decryptedData.confidence && <div className="intel-field"><span className="intel-label">Confidence</span><span>{decryptedData.confidence}</span></div>}
                  {decryptedData.risk_level && <div className="intel-field"><span className="intel-label">Risk</span><span>{decryptedData.risk_level} ({decryptedData.risk_score}/100)</span></div>}
                  {decryptedData.sharing_sector && <div className="intel-field"><span className="intel-label">Sector</span><span>{decryptedData.sharing_sector}</span></div>}
                </div>
                {decryptedData.description && (
                  <div className="intel-description">
                    <span className="intel-label">Description</span>
                    <p>{decryptedData.description}</p>
                  </div>
                )}
                {decryptedData.stix_bundle && (
                  <div className="intel-stix">
                    <span className="intel-label">STIX 2.1 Bundle ({decryptedData.stix_bundle.objects?.length || 0} objects)</span>
                    <div className="stix-objects">
                      {(decryptedData.stix_bundle.objects || []).map((obj, i) => (
                        <div key={i} className="stix-object">
                          <div className="stix-object-type">{obj.type}</div>
                          <div className="stix-object-name">{obj.name || obj.id}</div>
                          {obj.description && <div className="stix-object-desc">{obj.description}</div>}
                          {obj.pattern && <div className="stix-object-pattern"><code>{obj.pattern}</code></div>}
                          {obj.malware_types && <div className="stix-object-tags">{obj.malware_types.join(", ")}</div>}
                          {obj.labels && <div className="stix-object-tags">{obj.labels.join(", ")}</div>}
                          {obj.number_observed && <div className="stix-object-tags">{obj.number_observed} observations</div>}
                          {obj.sectors && <div className="stix-object-tags">Sectors: {obj.sectors.join(", ")}</div>}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
