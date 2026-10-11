
import { useEffect, useMemo, useState } from 'react'
import {
  Activity,
  ShieldCheck,
  LayoutDashboard,
  Database,
  Building2,
  FileCheck2,
  RefreshCw,
  Search,
  Wifi,
  AlertTriangle,
  LockKeyhole,
  ArrowLeft,
} from 'lucide-react'
import { api } from './api'
import LandingPage from './LandingPage.jsx'
import CTISubmissionForm from './CTISubmissionForm.jsx'
import './App.css'

const navigation = [
  { label: 'Overview', icon: LayoutDashboard },
  { label: 'Threat Intelligence', icon: Database },
  { label: 'Organizations', icon: Building2 },
  { label: 'Access Control', icon: LockKeyhole },
]

function getRiskClass(level, score) {
  const value = String(level || '').toLowerCase()
  const numericScore = Number(score)

  if (value === 'critical' || numericScore >= 80) return 'badge-critical'
  if (value === 'high' || numericScore >= 60) return 'badge-high'
  if (value === 'medium' || numericScore >= 30) return 'badge-medium'
  if (value === 'low' || numericScore < 30) return 'badge-low'

  return 'badge-neutral'
}

function App() {
  const [showLandingPage, setShowLandingPage] = useState(true)
  const [activePage, setActivePage] = useState('Overview')

  const [records, setRecords] = useState([])
  const [organizations, setOrganizations] = useState([])
  const [policies, setPolicies] = useState([])
  const [correlations, setCorrelations] = useState([])
  const [riskResults, setRiskResults] = useState([])

  const [loading, setLoading] = useState(true)
  const [submittingCTI, setSubmittingCTI] = useState(false)
  const [error, setError] = useState('')
  const [search, setSearch] = useState('')
  const [lastUpdated, setLastUpdated] = useState(null)

  async function loadDashboard() {
    setLoading(true)
    setError('')

    try {
      const results = await Promise.allSettled([
        api.getAdvancedCTI(),
        api.getOrganizations(),
        api.getPolicies(),
        api.getCorrelations(),
        api.getRisk(),
      ])

      const [
        ctiResult,
        orgResult,
        policyResult,
        correlationResult,
        riskResult,
      ] = results

      if (ctiResult.status !== 'fulfilled') {
        throw ctiResult.reason
      }

      const ctiData = ctiResult.value

      setRecords(
        Array.isArray(ctiData)
          ? ctiData
          : ctiData.records || [],
      )

      setOrganizations(
        orgResult.status === 'fulfilled'
          ? orgResult.value.organizations || []
          : [],
      )

      setPolicies(
        policyResult.status === 'fulfilled'
          ? policyResult.value.policies || []
          : [],
      )

      setCorrelations(
        correlationResult.status === 'fulfilled'
          ? correlationResult.value.correlations || []
          : [],
      )

      setRiskResults(
        riskResult.status === 'fulfilled'
          ? riskResult.value.results || []
          : [],
      )

      setLastUpdated(new Date())
    } catch (err) {
      setError(err.message || 'Unable to load dashboard data.')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadDashboard()
  }, [])

  const filteredRecords = useMemo(() => {
    const query = search.trim().toLowerCase()

    if (!query) return records

    return records.filter((record) =>
      [
        record.title,
        record.indicator_value,
        record.category,
        record.severity,
        record.status,
        record.sharing_sector,
      ]
        .filter(Boolean)
        .some((value) => String(value).toLowerCase().includes(query)),
    )
  }, [records, search])

  const criticalCount = records.filter(
    (record) =>
      String(record.risk_level || '').toLowerCase() === 'critical' ||
      Number(record.risk_score) >= 80,
  ).length

  const highCount = records.filter(
    (record) =>
      String(record.risk_level || '').toLowerCase() === 'high' ||
      (
        Number(record.risk_score) >= 60 &&
        Number(record.risk_score) < 80
      ),
  ).length

  const averageRisk = records.length
    ? Math.round(
        records.reduce(
          (total, record) =>
            total + (Number(record.risk_score) || 0),
          0,
        ) / records.length,
      )
    : 0

  const riskGroups = [
    {
      label: 'Critical',
      count: records.filter(
        (record) =>
          getRiskClass(record.risk_level, record.risk_score) ===
          'badge-critical',
      ).length,
      className: 'risk-critical',
    },
    {
      label: 'High',
      count: records.filter(
        (record) =>
          getRiskClass(record.risk_level, record.risk_score) ===
          'badge-high',
      ).length,
      className: 'risk-high',
    },
    {
      label: 'Medium',
      count: records.filter(
        (record) =>
          getRiskClass(record.risk_level, record.risk_score) ===
          'badge-medium',
      ).length,
      className: 'risk-medium',
    },
    {
      label: 'Low',
      count: records.filter(
        (record) =>
          getRiskClass(record.risk_level, record.risk_score) ===
          'badge-low',
      ).length,
      className: 'risk-low',
    },
  ]

  // Submit CTI through the existing Flask API.
  async function handleCTISubmission(record) {
    setSubmittingCTI(true)

    try {
      await api.submitCTI(record)
      await loadDashboard()
      setActivePage('Threat Intelligence')
    } finally {
      setSubmittingCTI(false)
    }
  }

  function renderOverview() {
    return (
      <>
        <div className="section-intro">
          <h2 className="section-heading">Security overview</h2>
          <p className="section-description">
            Monitor shared threat intelligence, assess risk, and review access activity.
          </p>
        </div>

        {error && <div className="panel error-state">{error}</div>}

        <section className="kpi-grid">
          <KpiCard
            icon={Database}
            label="CTI Records"
            value={records.length}
            note="Advanced intelligence records"
          />

          <KpiCard
            icon={AlertTriangle}
            label="Critical Risk"
            value={criticalCount}
            note="Records with risk score 80+"
            color="red"
          />

          <KpiCard
            icon={Activity}
            label="High Risk"
            value={highCount}
            note="High-priority indicators"
            color="yellow"
          />

          <KpiCard
            icon={Building2}
            label="Organizations"
            value={organizations.length}
            note="Registered organizations"
          />
        </section>

        <section className="content-grid">
          <div className="panel">
            <div className="panel-heading">
              <div>
                <h3>Recent threat intelligence</h3>
                <p>Live records from your Flask API</p>
              </div>

              <button
                className="button-secondary"
                onClick={() => setActivePage('Threat Intelligence')}
              >
                View all
              </button>
            </div>

            {loading ? (
              <div className="loading-state">Loading CTI records...</div>
            ) : (
              <RecordsTable records={records.slice(0, 5)} />
            )}
          </div>

          <div className="panel">
            <div className="panel-heading">
              <div>
                <h3>Risk distribution</h3>
                <p>Calculated from loaded CTI records</p>
              </div>

              <ShieldCheck size={19} color="#5284f5" />
            </div>

            <div className="risk-list">
              {riskGroups.map((group) => {
                const percentage = records.length
                  ? (group.count / records.length) * 100
                  : 0

                return (
                  <div className="risk-row" key={group.label}>
                    <div className="risk-row-top">
                      <span>{group.label}</span>
                      <span>
                        {group.count} ({Math.round(percentage)}%)
                      </span>
                    </div>

                    <div className="risk-track">
                      <div
                        className={`risk-fill ${group.className}`}
                        style={{ width: `${percentage}%` }}
                      />
                    </div>
                  </div>
                )
              })}
            </div>

            <div className="risk-summary">
              <span>Average CTI risk score</span>
              <strong>{averageRisk}/100</strong>
            </div>
          </div>
        </section>

        <section className="panel organizations-panel">
          <div className="panel-heading">
            <div>
              <h3>Registered organizations</h3>
              <p>Organizations returned by the backend</p>
            </div>

            <Building2 size={19} color="#5284f5" />
          </div>

          {organizations.length ? (
            <div className="organization-list">
              {organizations.slice(0, 4).map((org, index) => (
                <div className="organization-item" key={org.id ?? index}>
                  <div className="organization-avatar">
                    <Building2 size={18} />
                  </div>

                  <div className="organization-info">
                    <strong>
                      {org.name || `Organization ${index + 1}`}
                    </strong>
                    <span>{org.sector || 'Sector not provided'}</span>
                  </div>

                  <span className="badge badge-neutral">
                    Trust: {org.trust_score ?? 'N/A'}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <div className="empty-state">
              {loading
                ? 'Loading organizations...'
                : 'No organizations returned.'}
            </div>
          )}
        </section>
      </>
    )
  }

  function renderThreatIntelligence() {
    return (
      <>
        <CTISubmissionForm
          onSubmit={handleCTISubmission}
          submitting={submittingCTI}
        />

        <section className="panel">
          <div className="panel-heading">
            <div>
              <h2 className="section-heading">Threat Intelligence Records</h2>
              <p className="section-description">
                Search and review records returned by the backend.
              </p>
            </div>

            <button
              className="button-secondary"
              onClick={loadDashboard}
              disabled={loading}
            >
              <RefreshCw size={15} />
              Refresh
            </button>
          </div>

          <div className="toolbar">
            <span className="record-count">
              {filteredRecords.length} of {records.length} records
            </span>

            <div className="search-box">
              <Search size={16} />
              <input
                className="search-input"
                placeholder="Search indicators..."
                value={search}
                onChange={(event) => setSearch(event.target.value)}
              />
            </div>
          </div>

          {error ? (
            <div className="error-state">{error}</div>
          ) : loading ? (
            <div className="loading-state">Loading records...</div>
          ) : (
            <RecordsTable records={filteredRecords} />
          )}
        </section>
      </>
    )
  }

  function renderOrganizations() {
    return (
      <section className="panel">
        <div className="panel-heading">
          <div>
            <h2 className="section-heading">Organizations</h2>
            <p className="section-description">
              Registered participants in the CTI-sharing prototype.
            </p>
          </div>

          <Building2 size={20} color="#5284f5" />
        </div>

        {organizations.length ? (
          <div className="table-wrapper">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Organization</th>
                  <th>Sector</th>
                  <th>Trust score</th>
                  <th>Policy violations</th>
                </tr>
              </thead>

              <tbody>
                {organizations.map((org, index) => (
                  <tr key={org.id ?? index}>
                    <td className="record-title">
                      {org.name || 'Unnamed'}
                    </td>
                    <td>{org.sector || 'N/A'}</td>
                    <td>{org.trust_score ?? 'N/A'}</td>
                    <td>{org.policy_violations ?? 'N/A'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="empty-state">
            No organization data available.
          </div>
        )}
      </section>
    )
  }

  function renderAccessControl() {
    return (
      <section className="panel">
        <div className="panel-heading">
          <div>
            <h2 className="section-heading">Access Control</h2>
            <p className="section-description">
              Overview of policy-related data returned by the backend.
            </p>
          </div>

          <FileCheck2 size={20} color="#5284f5" />
        </div>

        <div className="notice">
          <AlertTriangle size={18} />
          <p>
            This page displays prototype data only. A policy list is shown only
            if the backend provides it. Actual CTI access enforcement and
            PR-RABE cryptographic protection have not yet been implemented.
          </p>
        </div>

        {policies.length ? (
          <div className="table-wrapper">
            <table className="data-table">
              <thead>
                <tr>
                  {Object.keys(policies[0]).map((key) => (
                    <th key={key}>{key.replaceAll('_', ' ')}</th>
                  ))}
                </tr>
              </thead>

              <tbody>
                {policies.map((policy, index) => (
                  <tr key={index}>
                    {Object.keys(policies[0]).map((key) => (
                      <td key={key}>
                        {String(policy[key] ?? 'N/A')}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="empty-state">
            No policy list was returned by the available GET endpoint.
            Policy evaluation is a separate operation.
          </div>
        )}

        <div className="policy-summary">
          <div>
            <span>Correlation results</span>
            <strong>{correlations.length}</strong>
          </div>

          <div>
            <span>Risk analysis results</span>
            <strong>{riskResults.length}</strong>
          </div>
        </div>
      </section>
    )
  }

  const pageContent = {
    Overview: renderOverview,
    'Threat Intelligence': renderThreatIntelligence,
    Organizations: renderOrganizations,
    'Access Control': renderAccessControl,
  }

  if (showLandingPage) {
    return (
      <LandingPage
        onOpenDashboard={() => setShowLandingPage(false)}
      />
    )
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-icon">
            <ShieldCheck size={23} />
          </div>

          <div>
            <h2>CTI-BTP</h2>
            <small>THREAT INTELLIGENCE</small>
          </div>
        </div>

        <div className="nav-label">WORKSPACE</div>

        <nav className="nav-list">
          {navigation.map(({ label, icon: Icon }) => (
            <button
              key={label}
              className={`nav-item ${activePage === label ? 'active' : ''}`}
              onClick={() => setActivePage(label)}
            >
              <Icon size={18} />
              <span>{label}</span>
            </button>
          ))}
        </nav>

        <div className="sidebar-footer">
          <span className="status-dot" />
          API connection
          <br />
          <span style={{ color: '#34d399' }}>
            Development environment
          </span>
          <br />
          Flask · React · SQLite
        </div>
      </aside>

      <main className="main-area">
        <header className="topbar">
          <div>
            <h1>{activePage}</h1>
            <p>Risk-adaptive cyber threat intelligence sharing</p>
          </div>

          <div className="topbar-right">
            <span className="connection-badge">
              <Wifi
                size={13}
                style={{ display: 'inline', marginRight: 5 }}
              />
              {error
                ? 'API issue'
                : loading
                  ? 'Connecting...'
                  : 'API connected'}
            </span>

            <button
              className="button-secondary refresh-button"
              onClick={loadDashboard}
              title="Refresh dashboard data"
              aria-label="Refresh dashboard data"
              disabled={loading}
            >
              <RefreshCw size={15} />
            </button>

            <button
              className="button-secondary refresh-button"
              onClick={() => setShowLandingPage(true)}
              title="Back to marketing page"
              aria-label="Back to marketing page"
            >
              <ArrowLeft size={15} />
            </button>

            <div className="avatar">S</div>
          </div>
        </header>

        <div className="page-content">
          <div className="toolbar dashboard-toolbar">
            <div>
              <span className="record-count">
                {lastUpdated
                  ? `Last updated ${lastUpdated.toLocaleTimeString()}`
                  : 'Waiting for API data'}
              </span>
            </div>

            <div className="toolbar-actions">
              <span className="record-count">Live API data</span>

              <button
                className="button-primary"
                onClick={loadDashboard}
                disabled={loading}
              >
                <RefreshCw size={14} />
                Refresh data
              </button>
            </div>
          </div>

          {pageContent[activePage]()}
        </div>
      </main>
    </div>
  )
}

function KpiCard({ icon: Icon, label, value, note, color }) {
  const iconStyle =
    color === 'red'
      ? { color: '#d94d65', background: '#fff0f3' }
      : color === 'yellow'
        ? { color: '#b7791f', background: '#fff6e5' }
        : {}

  return (
    <article className="kpi-card">
      <div className="kpi-top">
        <span className="kpi-label">{label}</span>
        <span className="kpi-icon" style={iconStyle}>
          <Icon size={18} />
        </span>
      </div>

      <div className="kpi-value">{value}</div>
      <div className="kpi-note">{note}</div>
    </article>
  )
}

function RecordsTable({ records }) {
  if (!records.length) {
    return (
      <div className="empty-state">
        No CTI records to display.
      </div>
    )
  }

  return (
    <div className="table-wrapper">
      <table className="data-table">
        <thead>
          <tr>
            <th>Threat / Indicator</th>
            <th>Category</th>
            <th>Risk</th>
            <th>Status</th>
          </tr>
        </thead>

        <tbody>
          {records.map((record, index) => (
            <tr key={record.id ?? index}>
              <td>
                <div className="record-title">
                  {record.title || 'Untitled record'}
                </div>
                <div className="record-subtitle">
                  {record.indicator_value || 'No indicator provided'}
                </div>
              </td>

              <td>{record.category || 'N/A'}</td>

              <td>
                <span
                  className={`badge ${getRiskClass(
                    record.risk_level,
                    record.risk_score,
                  )}`}
                >
                  {record.risk_level || record.severity || 'Unknown'} ·{' '}
                  {record.risk_score ?? 'N/A'}
                </span>
              </td>

              <td>
                <span className="badge badge-neutral">
                  {record.status || 'Unknown'}
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export default App
