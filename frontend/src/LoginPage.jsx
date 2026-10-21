import { useEffect, useRef, useState } from 'react'
import {
  AlertCircle,
  ArrowLeft,
  Building2,
  CheckCircle2,
  Eye,
  EyeOff,
  Gauge,
  History,
  Info,
  Loader2,
  LockKeyhole,
  Plus,
  Share2,
  ShieldCheck,
  UserPlus,
} from 'lucide-react'
import { api, ApiError, API_BASE_URL, getAccessToken } from './api'
import './LoginPage.css'

const SECTORS = ['Finance', 'Healthcare', 'Education', 'Technology', 'Government', 'Energy']
const MIN_PASSWORD = 8
const MAX_PASSWORD = 128

const HIGHLIGHTS = [
  {
    icon: Share2,
    title: 'Share indicators once',
    text: 'Submit an indicator and make it available to partner organizations in your sector.',
  },
  {
    icon: Gauge,
    title: 'Scores backed by evidence',
    text: 'Risk reflects severity, confidence, source reliability, and how many organizations report it.',
  },
  {
    icon: History,
    title: 'Disagreements stay visible',
    text: 'When reports conflict on severity, the timeline shows both sides instead of hiding one.',
  },
]

function friendlyError(err, mode) {
  if (err instanceof ApiError) {
    if (mode === 'login' && err.status === 401) {
      return 'Incorrect email or password.'
    }
    if (err.status === 409) {
      return 'An account with this email already exists. Sign in instead.'
    }
    if (err.status === 429) {
      return 'Too many attempts. Wait a moment and try again.'
    }
  }
  return err?.message || 'Something went wrong. Please try again.'
}

function LoginPage({ onLogin, onBack, notice = '' }) {
  const [mode, setMode] = useState('login')
  const [name, setName] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')

  const [organizations, setOrganizations] = useState([])
  const [selectedOrgId, setSelectedOrgId] = useState('')
  const [orgMode, setOrgMode] = useState('existing') // 'existing' | 'new'
  const [newOrgName, setNewOrgName] = useState('')
  const [newOrgSector, setNewOrgSector] = useState('Finance')

  const formRef = useRef(null)
  const mounted = useRef(true)

  useEffect(() => {
    mounted.current = true
    return () => {
      mounted.current = false
    }
  }, [])

  useEffect(() => {
    fetch(`${API_BASE_URL}/api/organizations/public`)
      .then(r => r.ok ? r.json() : { organizations: [] })
      .then(d => { if (mounted.current) setOrganizations(d.organizations || []) })
      .catch(() => {})
  }, [])

  // Move focus to the first empty field whenever the form changes mode.
  useEffect(() => {
    const inputs = Array.from(formRef.current?.querySelectorAll('input') ?? [])
    const target = inputs.find((input) => !input.value) ?? inputs[0]
    target?.focus()
  }, [mode])

  const registering = mode === 'register'

  function switchMode(nextMode) {
    if (loading || nextMode === mode) return
    setMode(nextMode)
    setError('')
    setMessage('')
    setPassword('')
    setConfirmPassword('')
    setShowPassword(false)
    setSelectedOrgId('')
    setOrgMode('existing')
    setNewOrgName('')
    setNewOrgSector('Finance')
  }

  async function handleSubmit(event) {
    event.preventDefault()
    if (loading) return

    setError('')
    setMessage('')
    setLoading(true)

    const cleanEmail = email.trim().toLowerCase()

    try {
      if (registering) {
        const cleanName = name.trim()

        if (cleanName.length < 2) {
          throw new Error('Enter your full name.')
        }
        if (password.length < MIN_PASSWORD) {
          throw new Error(
            `Password must be at least ${MIN_PASSWORD} characters.`,
          )
        }
        if (password !== confirmPassword) {
          throw new Error('Passwords do not match.')
        }
        if (orgMode === 'existing' && !selectedOrgId) {
          throw new Error('Select an organization to join.')
        }
        if (orgMode === 'new' && newOrgName.trim().length < 2) {
          throw new Error('Organization name must be at least 2 characters.')
        }

        const regBody = {
          name: cleanName,
          email: cleanEmail,
          password,
        }
        if (orgMode === 'existing') {
          regBody.organization_id = parseInt(selectedOrgId)
        } else {
          regBody.new_org_name = newOrgName.trim()
          regBody.new_org_sector = newOrgSector
        }

        const regRes = await fetch(`${API_BASE_URL}/api/auth/register`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(regBody),
        })
        const regData = await regRes.json().catch(() => ({}))
        if (!regRes.ok) {
          throw new ApiError(regData.error || 'Registration failed', { status: regRes.status, data: regData })
        }

        if (!mounted.current) return

        // Refresh org list in case a new org was just created
        fetch(`${API_BASE_URL}/api/organizations/public`)
          .then(r => r.ok ? r.json() : { organizations: [] })
          .then(d => { if (mounted.current) setOrganizations(d.organizations || []) })
          .catch(() => {})

        setEmail(cleanEmail)
        setMessage('Account created. Sign in to continue.')
        setMode('login')
        setPassword('')
        setConfirmPassword('')
      } else {
        // api.login stores the token itself.
        const result = await api.login(cleanEmail, password)

        if (!result?.access_token && !result?.token) {
          throw new Error('The server did not return an access token.')
        }

        onLogin(result.user)
        return // This page is about to unmount; skip further state updates.
      }
    } catch (err) {
      if (mounted.current) setError(friendlyError(err, mode))
    } finally {
      if (mounted.current) setLoading(false)
    }
  }

  const submitLabel = registering ? 'Create account' : 'Sign in'

  return (
    <main className="login-page">
      <div className="login-shell">
        <aside className="login-aside" aria-label="About CTI-BTP">
          <div className="login-brand">
            <span className="login-brand-icon" aria-hidden="true">
              <ShieldCheck size={22} />
            </span>
            <span className="login-brand-name">CTI-BTP</span>
          </div>

          <h2 className="login-aside-title">
            Share threat intelligence with the organizations you trust.
          </h2>

          <ul className="login-highlights">
            {HIGHLIGHTS.map(({ icon: Icon, title, text }) => (
              <li key={title}>
                <span className="login-highlight-icon" aria-hidden="true">
                  <Icon size={18} />
                </span>
                <div>
                  <strong>{title}</strong>
                  <p>{text}</p>
                </div>
              </li>
            ))}
          </ul>
        </aside>

        <section className="login-card">
          <button
            className="login-back"
            type="button"
            onClick={onBack}
            disabled={loading}
          >
            <ArrowLeft size={16} aria-hidden="true" />
            Back to home
          </button>

          <h1 className="login-title">
            {registering ? 'Create your account' : 'Sign in to CTI-BTP'}
          </h1>
          <p className="login-description">
            {registering
              ? 'Register to view and submit threat intelligence.'
              : 'Use your work email to open the dashboard.'}
          </p>

          <div className="login-tabs" role="tablist" aria-label="Account">
            <button
              type="button"
              role="tab"
              aria-selected={!registering}
              className={`login-tab ${!registering ? 'is-active' : ''}`}
              onClick={() => switchMode('login')}
              disabled={loading}
            >
              Sign in
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={registering}
              className={`login-tab ${registering ? 'is-active' : ''}`}
              onClick={() => switchMode('register')}
              disabled={loading}
            >
              Create account
            </button>
          </div>

          {notice && !error && !message && (
            <p className="login-alert login-notice" role="status">
              <Info size={16} aria-hidden="true" />
              <span>{notice}</span>
            </p>
          )}

          <form ref={formRef} onSubmit={handleSubmit} aria-busy={loading}>
            {registering && (
              <div className="login-field">
                <label htmlFor="register-name">Full name</label>
                <input
                  id="register-name"
                  type="text"
                  autoComplete="name"
                  placeholder="Jane Doe"
                  value={name}
                  onChange={(event) => setName(event.target.value)}
                  minLength={2}
                  maxLength={100}
                  required
                />
              </div>
            )}

            <div className="login-field">
              <label htmlFor="login-email">Email address</label>
              <input
                id="login-email"
                type="email"
                autoComplete="email"
                autoCapitalize="none"
                spellCheck={false}
                placeholder="you@company.com"
                value={email}
                onChange={(event) => setEmail(event.target.value)}
                maxLength={254}
                required
              />
            </div>

            <div className="login-field">
              <label htmlFor="login-password">Password</label>
              <div className="login-password-field">
                <input
                  id="login-password"
                  type={showPassword ? 'text' : 'password'}
                  autoComplete={registering ? 'new-password' : 'current-password'}
                  placeholder={
                    registering
                      ? `At least ${MIN_PASSWORD} characters`
                      : 'Enter your password'
                  }
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  minLength={registering ? MIN_PASSWORD : undefined}
                  maxLength={MAX_PASSWORD}
                  required
                />
                <button
                  type="button"
                  className="login-toggle"
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                  aria-pressed={showPassword}
                  onClick={() => setShowPassword((current) => !current)}
                >
                  {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                </button>
              </div>
            </div>

            {registering && (
              <div className="login-field">
                <label htmlFor="confirm-password">Confirm password</label>
                <input
                  id="confirm-password"
                  type={showPassword ? 'text' : 'password'}
                  autoComplete="new-password"
                  placeholder="Re-enter your password"
                  value={confirmPassword}
                  onChange={(event) => setConfirmPassword(event.target.value)}
                  maxLength={MAX_PASSWORD}
                  required
                />
              </div>
            )}

            {registering && (
              <div className="login-field">
                <label>Organization</label>
                <div className="login-org-tabs">
                  <button
                    type="button"
                    className={`login-org-tab ${orgMode === 'existing' ? 'is-active' : ''}`}
                    onClick={() => setOrgMode('existing')}
                  >
                    <Building2 size={14} /> Join existing
                  </button>
                  <button
                    type="button"
                    className={`login-org-tab ${orgMode === 'new' ? 'is-active' : ''}`}
                    onClick={() => setOrgMode('new')}
                  >
                    <Plus size={14} /> Create new
                  </button>
                </div>

                {orgMode === 'existing' ? (
                  <select
                    value={selectedOrgId}
                    onChange={(e) => setSelectedOrgId(e.target.value)}
                    className="login-org-select"
                  >
                    <option value="">Select your organization...</option>
                    {organizations.map((org) => (
                      <option key={org.id} value={org.id}>
                        {org.name} ({org.sector})
                      </option>
                    ))}
                  </select>
                ) : (
                  <div className="login-org-new">
                    <input
                      type="text"
                      placeholder="Organization name"
                      value={newOrgName}
                      onChange={(e) => setNewOrgName(e.target.value)}
                      maxLength={100}
                    />
                    <select
                      value={newOrgSector}
                      onChange={(e) => setNewOrgSector(e.target.value)}
                    >
                      {SECTORS.map((s) => (
                        <option key={s} value={s}>{s}</option>
                      ))}
                    </select>
                  </div>
                )}
              </div>
            )}

            {error && (
              <p className="login-alert login-error" role="alert">
                <AlertCircle size={16} aria-hidden="true" />
                <span>{error}</span>
              </p>
            )}

            {message && (
              <p className="login-alert login-success" role="status">
                <CheckCircle2 size={16} aria-hidden="true" />
                <span>{message}</span>
              </p>
            )}

            <button className="login-submit" type="submit" disabled={loading}>
              {loading ? (
                <Loader2 size={17} className="login-spinner" aria-hidden="true" />
              ) : registering ? (
                <UserPlus size={17} aria-hidden="true" />
              ) : (
                <LockKeyhole size={17} aria-hidden="true" />
              )}
              {loading ? 'Please wait…' : submitLabel}
            </button>
          </form>

          <p className="login-security-note">
            This is a prototype environment. Don't reuse a password from another
            service.
          </p>
        </section>
      </div>
    </main>
  )
}

export default LoginPage
