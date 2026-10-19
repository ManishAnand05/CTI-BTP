import { useMemo, useRef, useState, useEffect } from 'react'
import { API_BASE_URL, getAccessToken } from './api'
import './PDFIntelligence.css'

const MAX_PDF_BYTES = 15 * 1024 * 1024
const EXTRACT_TIMEOUT_MS = 60000
const INDICATOR_TYPES = ['all', 'domain', 'ip', 'url', 'cve', 'sha1', 'sha256', 'md5', 'attack_technique']
const HASH_TYPES = new Set(['md5', 'sha1', 'sha256'])
const GAUGE_CIRCUMFERENCE = 339.29

const INITIAL_REPORT = { threatName: '' }
const REPORT_FIELDS = [{ key: 'threatName', label: 'Report title (optional)', placeholder: 'e.g. Play Ransomware Advisory' }]

function displayType(type) { return String(type || 'unknown').replaceAll('_', ' ').toUpperCase() }
function typeClass(type) { return `t-${['cve', 'attack_technique', 'md5', 'sha1', 'sha256', 'domain', 'url', 'ip'].includes(type) ? type : 'other'}` }

function validateFile(file) {
  if (!file) return ''
  if (!file.name.toLowerCase().endsWith('.pdf')) return 'Only PDF files are supported.'
  if (file.size === 0) return 'The selected file is empty.'
  if (file.size > MAX_PDF_BYTES) return 'This PDF is larger than the 15 MB limit.'
  return ''
}

async function readJson(response) { try { return await response.json() } catch { return null } }
function errorMessage(status, data) {
  const message = data?.error || data?.message
  if (message) return message
  if (status === 401) return 'Your session expired. Please sign in again.'
  return `PDF extraction failed (HTTP ${status}).`
}

function evidenceEntries(item) {
  const raw = item.evidence
  if (!raw) return []
  if (typeof raw === 'string') return [{ page: item.pages?.[0] ?? null, text: raw }]
  return raw.map((entry) => typeof entry === 'string'
    ? { page: null, text: entry }
    : { page: entry.page ?? null, text: entry.evidence ?? entry.text ?? '' })
}

function downloadBlob(filename, mime, text) {
  const blob = new Blob([text], { type: mime })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url; link.download = filename
  document.body.appendChild(link); link.click(); document.body.removeChild(link)
  URL.revokeObjectURL(url)
}

function CopyBtn({ text }) {
  const [copied, setCopied] = useState(false)
  const copy = async () => {
    try { await navigator.clipboard.writeText(text) } catch { return }
    setCopied(true); setTimeout(() => setCopied(false), 1800)
  }
  return <button type="button" className={`copy-btn ${copied ? 'done' : ''}`} onClick={copy}>{copied ? 'Copied' : 'Copy'}</button>
}

function ThreatGauge({ score }) {
  const offset = GAUGE_CIRCUMFERENCE * (1 - score / 100)
  return (
    <div className="gauge" style={{ '--offset': offset }} role="img">
      <svg viewBox="0 0 120 120">
        <circle className="gauge-track" cx="60" cy="60" r="54" />
        <circle className="gauge-fill" cx="60" cy="60" r="54" />
      </svg>
      <div className="gauge-center">
        <div className="gauge-score">{score}</div>
        <div className="gauge-caption">triage score</div>
      </div>
    </div>
  )
}

export default function PDFIntelligence({ orgContext }) {
  const [file, setFile] = useState(null)
  const [result, setResult] = useState(null)
  const [filter, setFilter] = useState('all')
  const [search, setSearch] = useState('')
  const [busy, setBusy] = useState(false)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  const [dragging, setDragging] = useState(false)
  const [showReport, setShowReport] = useState(false)
  const [report, setReport] = useState(INITIAL_REPORT)
  const [existingRecords, setExistingRecords] = useState([])
  const [loadingExisting, setLoadingExisting] = useState(false)
  const inputRef = useRef(null)

  // Fetch existing records for this org
  useEffect(() => {
    if (!orgContext) return
    async function fetchExisting() {
      setLoadingExisting(true)
      try {
        const token = getAccessToken()
        const res = await fetch(`${API_BASE_URL}/api/graph/temporal?org_id=${orgContext.id}`, {
          headers: { Authorization: `Bearer ${token}` }
        })
        if (res.ok) {
          const data = await res.json()
          // Only IOC nodes (not organizations)
          const iocNodes = (data.nodes || []).filter(n => n.type !== 'organization')
          setExistingRecords(iocNodes)
        }
      } catch (err) {
        console.error('Failed to load existing records', err)
      } finally {
        setLoadingExisting(false)
      }
    }
    fetchExisting()
  }, [orgContext])

  const selectFile = (selected) => {
    const problem = validateFile(selected)
    if (problem && inputRef.current) inputRef.current.value = ''
    setFile(problem ? null : selected)
    setError(problem)
  }
  const handleFileChange = (e) => selectFile(e.target.files?.[0] || null)
  const handleDrop = (e) => {
    e.preventDefault(); setDragging(false); if (busy) return
    selectFile(e.dataTransfer.files?.[0] || null)
  }

  const handleExtract = async (e) => {
    e.preventDefault()
    if (busy || !file) return
    const token = getAccessToken()
    if (!token) return window.dispatchEvent(new CustomEvent('cti:unauthorized'))

    setBusy(true); setError(''); setResult(null); setShowReport(false)
    const formData = new FormData(); formData.append('file', file)
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), EXTRACT_TIMEOUT_MS)

    try {
      const response = await fetch(`${API_BASE_URL}/api/cti/extract-pdf`, {
        method: 'POST',
        headers: { Accept: 'application/json', Authorization: `Bearer ${token}` },
        body: formData, signal: controller.signal,
      })
      const data = await readJson(response)
      if (!response.ok) throw new Error(errorMessage(response.status, data))
      setResult(data)
    } catch (err) {
      setError(err.name === 'AbortError' ? 'Extraction timed out.' : err.message)
    } finally {
      clearTimeout(timer); setBusy(false)
    }
  }

  const reset = () => { setResult(null); setFile(null); setError(''); setShowReport(false); setFilter('all'); setSearch('') }

  const extraction = result?.extraction
  const grouped = useMemo(() => extraction?.grouped_findings ?? [], [extraction])
  const techniques = useMemo(() => grouped.filter((i) => i.type === 'attack_technique'), [grouped])
  const cves = useMemo(() => grouped.filter((i) => i.type === 'cve'), [grouped])
  const hashes = useMemo(() => grouped.filter((i) => HASH_TYPES.has(i.type)), [grouped])

  const threat = useMemo(() => {
    const score = Math.min(100, cves.length * 18 + techniques.length * 7 + hashes.length * 3 + Math.min(grouped.length, 20))
    return { level: 'RULE-BASED TRIAGE', cls: 'elevated', icon: 'ℹ️', score }
  }, [techniques, cves, hashes, grouped])

  const mix = useMemo(() => {
    const counts = {}; grouped.forEach((i) => { counts[i.type] = (counts[i.type] || 0) + 1 })
    return Object.entries(counts).sort((a, b) => b[1] - a[1])
  }, [grouped])

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase()
    return grouped.filter((i) => {
      if (filter !== 'all' && i.type !== filter) return false
      if (q) {
        const haystack = `${i.value} ${i.type} ${i.context?.description || ''} ${evidenceEntries(i).map((e) => e.text).join(' ')}`.toLowerCase()
        if (!haystack.includes(q)) return false
      }
      return true
    }).sort((a, b) => String(a.type).localeCompare(String(b.type)))
  }, [grouped, filter, search])

  const setField = (key) => (e) => setReport((r) => ({ ...r, [key]: e.target.value }))

  const downloadSTIX = async () => {
    try {
      const token = getAccessToken()
      const response = await fetch(`${API_BASE_URL}/api/export/stix`, { headers: { Authorization: `Bearer ${token}` } })
      if (!response.ok) throw new Error("Failed to export STIX")
      const data = await response.json()
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" })
      const url = URL.createObjectURL(blob)
      const link = document.createElement("a")
      link.href = url; link.download = `cti_stix_bundle_${Date.now()}.json`
      document.body.appendChild(link); link.click(); document.body.removeChild(link)
    } catch (err) { alert("Error exporting STIX: " + err.message) }
  }

  const handleSaveAll = async () => {
    if (!grouped.length) return
    setSaving(true)
    let savedCount = 0; let failCount = 0; let lastErrorMsg = ""
    const token = getAccessToken()

    // Use ORG CONTEXT id, not logged-in user's org
    let orgId = orgContext?.id
    if (!orgId) {
      try {
        const userRes = await fetch(`${API_BASE_URL}/api/auth/me`, { headers: { Authorization: `Bearer ${token}` } })
        if (userRes.ok) {
          const userData = await userRes.json()
          if (userData.user?.organization_id) orgId = userData.user.organization_id
        }
      } catch (e) { console.error(e) }
      if (!orgId) orgId = 1
    }

    const ALLOWED_TYPES = ['ip', 'domain', 'md5', 'sha1', 'sha256', 'cve', 'attack_technique']
    const safeTimestamp = new Date(Date.now() - 3600000).toISOString()

    for (const item of grouped) {
      if (!ALLOWED_TYPES.includes(item.type)) continue
      try {
        const payload = {
          title: `Auto-extracted: ${item.type} - ${item.value}`,
          indicator_type: item.type, indicator_value: item.value,
          category: 'Network', severity: 'medium', confidence: 'medium',
          source_type: 'threat_research', source_reliability: 'verified',
          observed_at: safeTimestamp,
          description: item.context?.description || (evidenceEntries(item)[0]?.text) || "Extracted from uploaded PDF",
          sharing_sector: orgContext?.sector || "Finance", organization_id: orgId
        }
        const res = await fetch(`${API_BASE_URL}/api/cti/submit`, {
          method: "POST",
          headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
          body: JSON.stringify(payload)
        })
        if (!res.ok) {
          const errData = await res.json().catch(() => ({}))
          lastErrorMsg = errData.error || `HTTP ${res.status}`; failCount++
        } else { savedCount++ }
      } catch (err) { lastErrorMsg = err.message; failCount++ }
    }

    setSaving(false)
    if (failCount > 0) alert(`Saved ${savedCount}. Failed ${failCount}.\n${lastErrorMsg}`)
    else alert(`Successfully saved ${savedCount} indicators for ${orgContext?.name || 'this organization'}!`)
  }

  return (
    <div className="pdf-page">
      <div className="shell">
        <header className="page-head">
          <h2>{orgContext ? `${orgContext.name} — PDF Intelligence` : 'PDF Intelligence'}</h2>
          <p className="section-desc">
            {orgContext
              ? `Upload threat reports on behalf of ${orgContext.name} (${orgContext.sector}).`
              : 'Drop in a threat advisory and get indicators extracted.'}
          </p>
        </header>

        {/* EXISTING RECORDS FOR THIS ORG */}
        {orgContext && (
          <div className="panel" style={{ marginBottom: '24px' }}>
            <h3>Already Submitted by {orgContext.name}</h3>
            <p className="section-desc">
              {loadingExisting
                ? 'Loading...'
                : `${existingRecords.length} indicators already in the database for this organization.`}
            </p>
            {existingRecords.length > 0 && (
              <div style={{ maxHeight: '200px', overflowY: 'auto', marginTop: '12px', border: '1px solid #e8e6f1', borderRadius: '8px', padding: '8px' }}>
                {existingRecords.slice(0, 20).map((r, i) => (
                  <div key={i} style={{ padding: '6px 8px', borderBottom: i < 19 ? '1px solid #f0eff6' : 'none', fontSize: '12px', display: 'flex', justifyContent: 'space-between' }}>
                    <span style={{ fontFamily: 'monospace', color: '#292454' }}>{r.label?.substring(0, 40)}</span>
                    <span className={`badge ${typeClass(r.type)}`} style={{ fontSize: '10px' }}>{displayType(r.type)}</span>
                  </div>
                ))}
                {existingRecords.length > 20 && (
                  <div style={{ padding: '6px 8px', fontSize: '11px', color: '#77758e', fontStyle: 'italic' }}>
                    ...and {existingRecords.length - 20} more
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {!extraction && (
          <div className="panel">
            <form onSubmit={handleExtract}>
              <label className={`upload-zone ${dragging ? 'dragging' : ''}`} htmlFor="cti-pdf"
                onDragOver={(e) => { e.preventDefault(); setDragging(true) }}
                onDragLeave={() => setDragging(false)} onDrop={handleDrop}>
                <div className="upload-icon">📄</div>
                <div className="upload-text">{dragging ? 'Release to upload' : 'Drop a PDF here, or click to browse'}</div>
                <div className="upload-hint">Advisories and threat reports up to 15 MB</div>
                <input ref={inputRef} id="cti-pdf" type="file" accept=".pdf" onChange={handleFileChange} disabled={busy} />
              </label>
              {file && <div className="file-chip">📎 <strong>{file.name}</strong> <span>{(file.size / 1024 / 1024).toFixed(2)} MB</span></div>}
              <div className="upload-actions">
                <button className="button-primary" type="submit" disabled={busy || !file}>
                  {busy ? 'Extracting…' : 'Extract indicators'}
                </button>
              </div>
            </form>
            {error && <div className="form-error">{error}</div>}
          </div>
        )}

        {extraction && (
          <>
            <section className={`overview ${threat.cls}`}>
              <ThreatGauge score={threat.score} />
              <div className="overview-body">
                <div className="threat-level">Triage <span className="level-pill">{threat.icon} {threat.level}</span></div>
                <p className="overview-sub">Analyzed {extraction.page_count} pages and found {grouped.length} unique indicators.</p>
                {mix.length > 0 && (
                  <>
                    <div className="mix-bar">{mix.map(([type, n]) => <div key={type} className={`mix-seg ${typeClass(type)}`} style={{ flex: n }} />)}</div>
                    <div className="mix-legend">{mix.map(([type, n]) => <span key={type} className={typeClass(type)}><i />{displayType(type)} · {n}</span>)}</div>
                  </>
                )}
                <div className="threat-meta"><span><b>Source</b> {result.filename}</span></div>
              </div>
            </section>

            <div className="kpi-grid">
              <div className="kpi-card"><div className="kpi-label">Total indicators</div><div className="kpi-value">{grouped.length}</div></div>
              <div className="kpi-card accent"><div className="kpi-label">ATT&CK techniques</div><div className="kpi-value">{techniques.length}</div></div>
              <div className="kpi-card danger"><div className="kpi-label">CVEs</div><div className="kpi-value">{cves.length}</div></div>
              <div className="kpi-card warning"><div className="kpi-label">Hashes</div><div className="kpi-value">{hashes.length}</div></div>
            </div>

            <div className="panel">
              <div className="panel-head">
                <div><h3>Extracted indicators</h3></div>
                <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
                  <button type="button" className="button-primary" onClick={handleSaveAll} disabled={saving} style={{ background: '#7062e8', color: '#fff' }}>
                    {saving ? 'Saving...' : `💾 Save for ${orgContext?.name || 'Org'}`}
                  </button>
                  <button type="button" className="button-secondary" onClick={downloadSTIX}>⬇ Export STIX</button>
                  <button type="button" className="button-secondary" onClick={() => downloadBlob('iocs.json', 'application/json', JSON.stringify(extraction, null, 2))}>Export JSON</button>
                  <button type="button" className="button-secondary" onClick={reset}>Analyze another</button>
                </div>
              </div>
              <div className="filter-bar">
                <select value={filter} onChange={(e) => setFilter(e.target.value)}>
                  {INDICATOR_TYPES.map((t) => <option key={t} value={t}>{t === 'all' ? 'All types' : displayType(t)}</option>)}
                </select>
                <input type="search" placeholder="Search..." value={search} onChange={(e) => setSearch(e.target.value)} />
              </div>
              <div className="table-container">
                <table className="data-table">
                  <thead><tr><th>Type</th><th>Indicator</th><th>Context</th><th>Evidence</th></tr></thead>
                  <tbody>
                    {filtered.map((item) => (
                      <tr key={`${item.type}-${item.value}`}>
                        <td><span className={`badge ${typeClass(item.type)}`}>{displayType(item.type)}</span></td>
                        <td style={{ maxWidth: 320 }}>
                          <div className="indicator-row">
                            <span className="indicator-val">{item.value}</span>
                            <CopyBtn text={item.value} />
                          </div>
                        </td>
                        <td style={{ maxWidth: 300 }}>
                          {item.context ? (
                            <div className="context-box">
                              {item.context.filename && <div className="context-row"><span className="context-label">File</span><span>{item.context.filename}</span></div>}
                              {item.context.description && <div className="context-row"><span className="context-label">About</span>{item.context.description}</div>}
                            </div>
                          ) : <span className="muted">—</span>}
                        </td>
                        <td className="evidence-cell">{evidenceEntries(item).map((e, i) => <div key={i}>{e.page && <span className="evidence-page">p.{e.page}</span>}{e.text}</div>)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  )
}