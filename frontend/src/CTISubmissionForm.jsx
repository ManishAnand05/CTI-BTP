import { useState, useEffect } from 'react'
import {
  FilePlus2,
  ShieldCheck,
  AlertCircle,
  LoaderCircle,
} from 'lucide-react'
import { API_BASE_URL, getAccessToken } from './api'
import './CTISubmissionForm.css'

const initialForm = {
  title: '',
  indicator_value: '',
  indicator_type: 'ip',
  category: 'network',
  severity: 'medium',
  confidence: 'medium',
  sharing_sector: 'Finance',
  source_type: 'threat_research',
  source_reliability: 'verified',
  observed_at: '',
  description: '',
}

function CTISubmissionForm() {
  const [form, setForm] = useState(initialForm)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [userOrg, setUserOrg] = useState(null)

  useEffect(() => {
    const token = getAccessToken()
    fetch(`${API_BASE_URL}/api/auth/me`, {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then(r => r.ok ? r.json() : null)
      .then(d => { if (d?.organization) setUserOrg(d.organization) })
      .catch(() => {})
  }, [])

  function updateField(event) {
    const { name, value } = event.target

    setForm((current) => ({
      ...current,
      [name]: value,
    }))

    setError('')
    setSuccess('')
  }

  async function handleSubmit(event) {
    event.preventDefault()
    setError('')
    setSuccess('')

    if (!form.title.trim()) {
      setError('Enter a title for this intelligence record.')
      return
    }

    if (
      form.indicator_type !== 'none' &&
      !form.indicator_value.trim()
    ) {
      setError('Enter an indicator value.')
      return
    }

    if (!form.description.trim()) {
      setError('Enter a description for the threat observation.')
      return
    }

    let observedAt = null

    if (form.observed_at) {
      const observationDate = new Date(form.observed_at)

      if (Number.isNaN(observationDate.getTime())) {
        setError('Enter a valid observation date and time.')
        return
      }

      if (observationDate.getTime() > Date.now()) {
        setError('Observation date and time cannot be in the future.')
        return
      }

      observedAt = observationDate.toISOString()
    }

    if (!userOrg) {
      setError('Your organization has not loaded yet. Please wait.')
      return
    }

    const payload = {
      ...form,
      organization_id: userOrg.id,
      title: form.title.trim(),
      indicator_value:
        form.indicator_type === 'none'
          ? ''
          : form.indicator_value.trim(),
      description: form.description.trim(),
      observed_at: observedAt,
    }

    setSubmitting(true)
    try {
      const token = getAccessToken()
      const res = await fetch(`${API_BASE_URL}/api/cti/submit`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify(payload),
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.error || 'Submission failed')

      setForm(initialForm)
      setSuccess(data.message || 'Threat intelligence submitted successfully.')
    } catch (err) {
      setError(err.message || 'Unable to submit the record.')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <section className="cti-form-panel">
      <div className="cti-form-heading">
        <div className="cti-form-heading-icon">
          <FilePlus2 size={21} />
        </div>

        <div>
          <h3>Submit threat intelligence</h3>
          <p>
            Add a structured CTI record for processing and risk assessment.
          </p>
        </div>
      </div>

      {error && (
        <div className="cti-form-message cti-form-error" role="alert">
          <AlertCircle size={17} />
          <span>{error}</span>
        </div>
      )}

      {success && (
        <div className="cti-form-message cti-form-success" role="status">
          <ShieldCheck size={17} />
          <span>{success}</span>
        </div>
      )}

      <form onSubmit={handleSubmit}>
        <div className="cti-form-grid">
          <label className="cti-field cti-field-wide">
            Record title *
            <input
              name="title"
              value={form.title}
              onChange={updateField}
              placeholder="Example: Suspicious network indicator"
              required
              maxLength={200}
            />
          </label>

          <label className="cti-field">
            Indicator type
            <select
              name="indicator_type"
              value={form.indicator_type}
              onChange={updateField}
            >
              <option value="ip">IP address</option>
              <option value="domain">Domain</option>
              <option value="url">URL</option>
              <option value="sha256">SHA-256 hash</option>
              <option value="cve">CVE</option>
              <option value="none">No specific indicator</option>
            </select>
          </label>

          <label className="cti-field">
            Indicator value
            <input
              name="indicator_value"
              value={form.indicator_value}
              onChange={updateField}
              placeholder={
                form.indicator_type === 'ip'
                  ? 'Example: 192.0.2.10'
                  : 'Enter the indicator'
              }
              required={form.indicator_type !== 'none'}
              disabled={form.indicator_type === 'none'}
            />
          </label>

          <label className="cti-field">
            Category
            <select
              name="category"
              value={form.category}
              onChange={updateField}
            >
              <option value="network">Network</option>
              <option value="malware">Malware</option>
              <option value="phishing">Phishing</option>
              <option value="vulnerability">Vulnerability</option>
              <option value="campaign">Campaign</option>
              <option value="cloud">Cloud</option>
              <option value="incident">Incident</option>
              <option value="other">Other</option>
            </select>
          </label>

          <label className="cti-field">
            Severity
            <select
              name="severity"
              value={form.severity}
              onChange={updateField}
            >
              <option value="low">Low</option>
              <option value="medium">Medium</option>
              <option value="high">High</option>
              <option value="critical">Critical</option>
              <option value="unknown">Unknown</option>
            </select>
          </label>

          <label className="cti-field">
            Confidence
            <select
              name="confidence"
              value={form.confidence}
              onChange={updateField}
            >
              <option value="low">Low</option>
              <option value="medium">Medium</option>
              <option value="high">High</option>
              <option value="unknown">Unknown</option>
            </select>
          </label>

          <label className="cti-field">
            Sharing sector
            <select
              name="sharing_sector"
              value={form.sharing_sector}
              onChange={updateField}
            >
              <option value="Finance">Finance</option>
              <option value="Healthcare">Healthcare</option>
              <option value="Education">Education</option>
              <option value="Technology">Technology</option>
              <option value="Government">Government</option>
              <option value="Energy">Energy</option>
              <option value="All">All sectors</option>
            </select>
          </label>

          <label className="cti-field">
            Source type
            <select
              name="source_type"
              value={form.source_type}
              onChange={updateField}
            >
              <option value="siem">SIEM</option>
              <option value="edr">EDR</option>
              <option value="incident_response">Incident response</option>
              <option value="threat_research">Threat research</option>
              <option value="external_feed">External feed</option>
              <option value="user_report">User report</option>
              <option value="other">Other</option>
            </select>
          </label>

          <label className="cti-field">
            Source reliability
            <select
              name="source_reliability"
              value={form.source_reliability}
              onChange={updateField}
            >
              <option value="unverified">Unverified</option>
              <option value="partial">Partial</option>
              <option value="verified">Verified</option>
            </select>
          </label>

          <label className="cti-field">
            Observation date and time
            <input
              type="datetime-local"
              name="observed_at"
              value={form.observed_at}
              onChange={updateField}
            />
            <small>
              When was the threat evidence actually observed? Leave empty
              if unknown.
            </small>
          </label>

          <label className="cti-field cti-field-wide">
            Description *
            <textarea
              name="description"
              value={form.description}
              onChange={updateField}
              placeholder="Describe the observation and its context..."
              rows={4}
              maxLength={3000}
              required
            />
          </label>
        </div>

        <div className="cti-form-footer">
          <p>* Required fields</p>

          <button
            className="cti-submit-button"
            type="submit"
            disabled={submitting}
          >
            {submitting ? (
              <>
                <LoaderCircle size={17} className="cti-spinner" />
                Submitting...
              </>
            ) : (
              <>
                <FilePlus2 size={17} />
                Submit intelligence
              </>
            )}
          </button>
        </div>
      </form>
    </section>
  )
}

export default CTISubmissionForm