import { useState, useEffect, useCallback } from "react";
import {
  ShieldOff, ShieldCheck, Lock, Unlock, Key, AlertCircle,
  CheckCircle2, Loader2, RefreshCw, ArrowDown, Zap, Database,
} from "lucide-react";
import { API_BASE_URL, getAccessToken } from "./api";
import "./RevocationDemo.css";

const hdrs = () => ({
  "Content-Type": "application/json",
  Authorization: `Bearer ${getAccessToken()}`,
});

export default function RevocationDemo() {
  const [status, setStatus] = useState(null);
  const [records, setRecords] = useState([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");
  const [err, setErr] = useState("");
  const [encryptResult, setEncryptResult] = useState(null);
  const [decryptResults, setDecryptResults] = useState({});
  const [revokeResult, setRevokeResult] = useState(null);
  const [selectedRecord, setSelectedRecord] = useState("");
  const [selectedPolicy, setSelectedPolicy] = useState("");
  const [revokeOrgId, setRevokeOrgId] = useState("");
  const [revokeAttr, setRevokeAttr] = useState("TRUST:HIGH");

  const load = useCallback(async () => {
    const [sRes, rRes] = await Promise.all([
      fetch(`${API_BASE_URL}/api/prrabe/status`, { headers: hdrs() }),
      fetch(`${API_BASE_URL}/api/cti/advanced`, { headers: hdrs() }),
    ]);
    if (sRes.ok) setStatus(await sRes.json());
    if (rRes.ok) {
      const d = await rRes.json();
      setRecords(d.records || (Array.isArray(d) ? d : []));
    }
    setLoading(false);
  }, []);

  useEffect(() => { load(); }, [load]);

  const flash = (m, isErr) => { setMsg(isErr ? "" : m); setErr(isErr ? m : ""); };

  const doEncrypt = async () => {
    if (!selectedRecord || !selectedPolicy) return;
    setBusy(true);
    flash("");
    const res = await fetch(`${API_BASE_URL}/api/prrabe/encrypt`, {
      method: "POST", headers: hdrs(),
      body: JSON.stringify({ record_id: parseInt(selectedRecord), policy: selectedPolicy }),
    });
    const d = await res.json();
    if (res.ok) {
      setEncryptResult(d);
      flash(`Encrypted record ${d.record_id} in ${d.elapsed_ms} ms`);
    } else {
      flash(d.error || "Encrypt failed", true);
    }
    await load();
    setBusy(false);
  };

  const doDecryptAll = async () => {
    if (!encryptResult) return;
    setBusy(true);
    flash("");
    setDecryptResults({});
    const results = {};
    for (const org of (status?.orgs || [])) {
      const res = await fetch(`${API_BASE_URL}/api/prrabe/decrypt`, {
        method: "POST", headers: hdrs(),
        body: JSON.stringify({ record_id: parseInt(encryptResult.record_id), organization_id: org.org_id }),
      });
      const d = await res.json();
      results[org.org_id] = d;
    }
    setDecryptResults(results);
    flash("Decryption attempts complete");
    setBusy(false);
  };

  const doDecryptOrg = async (orgId) => {
    setBusy(true);
    const res = await fetch(`${API_BASE_URL}/api/prrabe/decrypt`, {
      method: "POST", headers: hdrs(),
      body: JSON.stringify({ record_id: parseInt(encryptResult.record_id), organization_id: orgId }),
    });
    const d = await res.json();
    setDecryptResults(prev => ({ ...prev, [orgId]: d }));
    setBusy(false);
  };

  const doRevoke = async () => {
    if (!revokeOrgId || !revokeAttr) return;
    setBusy(true);
    flash("");
    setRevokeResult(null);
    const res = await fetch(`${API_BASE_URL}/api/prrabe/revoke`, {
      method: "POST", headers: hdrs(),
      body: JSON.stringify({ organization_id: parseInt(revokeOrgId), attribute: revokeAttr }),
    });
    const d = await res.json();
    if (res.ok) {
      setRevokeResult(d);
      flash(`${d.note}`);
      setDecryptResults({});
    } else {
      flash(d.error || "Revoke failed", true);
    }
    await load();
    setBusy(false);
  };

  if (loading) return <div className="rd-loading"><Loader2 className="spin" size={24} /> Loading...</div>;

  if (!status?.aggregated) {
    return (
      <div className="rd-page">
        <div className="rd-header">
          <h2><ShieldOff size={22} /> Revocation Demo</h2>
        </div>
        <div className="rd-flash error"><AlertCircle size={16} /> PR-RABE system not aggregated. Complete the Key Ceremony first.</div>
      </div>
    );
  }

  const orgList = status?.orgs || [];

  return (
    <div className="rd-page">
      <div className="rd-header">
        <h2><ShieldOff size={22} /> PR-RABE Revocation Demo</h2>
        <p>Encrypt a CTI record, attempt decryption from each org, then revoke an attribute and see who loses access. <strong>No organisation keys change</strong> — only the AGK rotates.</p>
      </div>

      {msg && <div className="rd-flash success"><CheckCircle2 size={16} /> {msg}</div>}
      {err && <div className="rd-flash error"><AlertCircle size={16} /> {err}</div>}

      {/* ── Step 1: Encrypt ── */}
      <div className="rd-card">
        <div className="rd-card-head"><Lock size={18} /><h3>Step 1: Encrypt a CTI Record</h3></div>
        <div className="rd-form-row">
          <label>
            CTI Record
            <select value={selectedRecord} onChange={e => setSelectedRecord(e.target.value)}>
              <option value="">Select...</option>
              {records.map(r => <option key={r.id} value={r.id}>{r.title} ({r.severity})</option>)}
            </select>
          </label>
          <label>
            Access Policy (LSSS)
            <select value={selectedPolicy} onChange={e => setSelectedPolicy(e.target.value)}>
              <option value="">Select...</option>
              <option value="(SECTOR:FINANCE AND TRUST:HIGH)">SECTOR:FINANCE AND TRUST:HIGH</option>
              <option value="(SECTOR:FINANCE AND TRUST:MEDIUM)">SECTOR:FINANCE AND TRUST:MEDIUM</option>
              <option value="(SECTOR:HEALTHCARE AND TRUST:HIGH)">SECTOR:HEALTHCARE AND TRUST:HIGH</option>
              <option value="(TRUST:HIGH)">TRUST:HIGH (any sector)</option>
              <option value="(TRUST:MEDIUM)">TRUST:MEDIUM (any sector)</option>
            </select>
          </label>
          <button className="rd-btn primary" onClick={doEncrypt} disabled={busy || !selectedRecord || !selectedPolicy}>
            <Zap size={14} /> Encrypt with PR-RABE
          </button>
        </div>

        {encryptResult && (
          <div className="rd-encrypt-result">
            <div className="rd-meta">
              <span><strong>Record:</strong> {encryptResult.record_id}</span>
              <span><strong>Policy:</strong> <code>{encryptResult.policy}</code></span>
              <span><strong>Public names:</strong> {encryptResult.public_names?.join(", ")}</span>
              <span><strong>Values hidden:</strong> Yes (policy hiding)</span>
              <span><strong>Time:</strong> {encryptResult.elapsed_ms} ms</span>
            </div>
          </div>
        )}
      </div>

      {/* ── Step 2: Decrypt from each org ── */}
      {encryptResult && (
        <div className="rd-card">
          <div className="rd-card-head"><Unlock size={18} /><h3>Step 2: Decryption Attempts</h3></div>
          <p>Each org attempts to decrypt using its helper key + secret key.</p>

          <div className="rd-org-results">
            {orgList.map(org => {
              const result = decryptResults[org.org_id];
              return (
                <div key={org.org_id} className={`rd-org-row ${result ? (result.success ? "granted" : "denied") : ""}`}>
                  <div className="rd-org-info">
                    <strong>{org.org_name}</strong>
                    <small>{org.attributes?.join(", ")}</small>
                  </div>
                  <div className="rd-org-result">
                    {result ? (
                      result.success ? (
                        <span className="rd-badge granted"><ShieldCheck size={14} /> ACCESS</span>
                      ) : (
                        <span className="rd-badge denied"><ShieldOff size={14} /> BLOCKED — {result.reason}</span>
                      )
                    ) : (
                      <button className="rd-btn small" onClick={() => doDecryptOrg(org.org_id)} disabled={busy}>
                        <Key size={12} /> Try Decrypt
                      </button>
                    )}
                    {result?.elapsed_ms && <small className="rd-timing">{result.elapsed_ms} ms</small>}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* ── Step 3: Revoke ── */}
      {encryptResult && (
        <div className="rd-card revoke">
          <div className="rd-card-head"><ShieldOff size={18} /><h3>Step 3: Revoke an Attribute (AGK Rotation)</h3></div>
          <p>Select an org and attribute to revoke. The AGK rotates and affected records are re-encrypted. <strong>No org's private key changes.</strong></p>
          <div className="rd-form-row">
            <label>
              Organisation
              <select value={revokeOrgId} onChange={e => setRevokeOrgId(e.target.value)}>
                <option value="">Select...</option>
                {orgList.map(o => <option key={o.org_id} value={o.org_id}>{o.org_name}</option>)}
              </select>
            </label>
            <label>
              Attribute to Revoke
              <select value={revokeAttr} onChange={e => setRevokeAttr(e.target.value)}>
                <option value="TRUST:HIGH">TRUST:HIGH</option>
                <option value="TRUST:MEDIUM">TRUST:MEDIUM</option>
                <option value="SECTOR:FINANCE">SECTOR:FINANCE</option>
                <option value="SECTOR:HEALTHCARE">SECTOR:HEALTHCARE</option>
              </select>
            </label>
            <button className="rd-btn danger" onClick={doRevoke} disabled={busy || !revokeOrgId}>
              <ShieldOff size={14} /> Revoke & Rotate AGK
            </button>
          </div>

          {revokeResult && (
            <div className="rd-revoke-result">
              <div className="rd-meta">
                <span><strong>Org:</strong> {revokeResult.org_name}</span>
                <span><strong>Attribute:</strong> {revokeResult.attribute}</span>
                <span><strong>AGK Version:</strong> v{revokeResult.new_agk_version}</span>
                <span><strong>Records re-encrypted:</strong> {revokeResult.records_reencrypted}</span>
                <span><strong>Time:</strong> {revokeResult.elapsed_ms} ms</span>
              </div>
              <p className="rd-revoke-note">
                <ArrowDown size={14} /> Now try decrypting again — the revoked org will be <strong>BLOCKED</strong>. Their key pair hasn't changed, but the AGK they need has rotated.
              </p>
            </div>
          )}
        </div>
      )}

      {/* ── AGK Status ── */}
      {Object.keys(status?.agk_groups || {}).length > 0 && (
        <div className="rd-card">
          <div className="rd-card-head"><Database size={18} /><h3>AGK Group Status</h3></div>
          <table className="rd-agk-table">
            <thead><tr><th>Attribute</th><th>Version</th><th>Members</th></tr></thead>
            <tbody>
              {Object.entries(status.agk_groups).map(([attr, info]) => (
                <tr key={attr}>
                  <td><code>{attr}</code></td>
                  <td>v{info.version}</td>
                  <td>{info.member_count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <button className="rd-btn secondary" onClick={() => { load(); flash(""); setDecryptResults({}); }} style={{ marginTop: 12 }}>
        <RefreshCw size={14} /> Refresh
      </button>
    </div>
  );
}
