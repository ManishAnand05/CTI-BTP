
import {
  ArrowRight,
  ArrowUpRight,
  ShieldCheck,
  Network,
  LockKeyhole,
  Activity,
  Building2,
  Database,
  Fingerprint,
  CheckCircle2,
  ChevronRight,
  Globe2,
  Radar,
  Zap,
} from 'lucide-react'
import './LandingPage.css'

const features = [
  {
    icon: Network,
    number: '01',
    title: 'Threat intelligence processing',
    description:
      'Normalize, organize, and analyze threat indicators from multiple sources in a common workflow.',
    color: 'violet',
  },
  {
    icon: Activity,
    number: '02',
    title: 'Risk-adaptive decisions',
    description:
      'Evaluate risk levels and organizational attributes to support context-aware access decisions.',
    color: 'blue',
  },
  {
    icon: LockKeyhole,
    number: '03',
    title: 'Privacy-preserving sharing',
    description:
      'Explore attribute-based encryption as a research direction for controlled cross-organizational intelligence sharing.',
    color: 'green',
  },
]

const workflow = [
  {
    icon: Database,
    title: 'Collect',
    description: 'Receive threat intelligence from participating sources.',
  },
  {
    icon: Radar,
    title: 'Analyze',
    description: 'Normalize indicators and assess their risk.',
  },
  {
    icon: ShieldCheck,
    title: 'Evaluate',
    description: 'Apply organizational attributes and policy rules.',
  },
  {
    icon: Fingerprint,
    title: 'Protect',
    description: 'Develop privacy-preserving sharing mechanisms.',
  },
]

function LandingPage({ onOpenDashboard }) {
  return (
    <div className="landing-page">
      <header className="landing-nav">
        <a className="landing-brand" href="#home" aria-label="CTI-BTP home">
          <span className="landing-brand-icon">
            <ShieldCheck size={23} />
          </span>
          <span className="landing-brand-copy">
            <strong>CTI-BTP</strong>
            <small>THREAT INTELLIGENCE</small>
          </span>
        </a>

        <nav className="landing-nav-links" aria-label="Main navigation">
          <a href="#features">Features</a>
          <a href="#workflow">How it works</a>
          <a href="#research">Research focus</a>
        </nav>

        <button
          className="landing-nav-cta"
          onClick={onOpenDashboard}
        >
          Open dashboard <ArrowUpRight size={16} />
        </button>
      </header>

      <main id="home">
        <section className="landing-hero">
          <div className="landing-hero-copy">
            <div className="landing-eyebrow">
              <span className="landing-eyebrow-dot" />
              CYBERSECURITY RESEARCH PROJECT
            </div>

            <h1>
              Share intelligence.
              <br />
              <span>Strengthen security.</span>
            </h1>

            <p className="landing-hero-description">
              Explore risk-adaptive and privacy-preserving cyber threat
              intelligence sharing across organizations, built around
              structured intelligence processing and policy-based access
              decisions.
            </p>

            <div className="landing-hero-actions">
              <button
                className="landing-primary-button"
                onClick={onOpenDashboard}
              >
                Explore the dashboard <ArrowRight size={17} />
              </button>
              <a className="landing-secondary-link" href="#features">
                Discover the platform <ChevronRight size={17} />
              </a>
            </div>

            <div className="landing-trust-note">
              <CheckCircle2 size={16} />
              <span>Research prototype with live local backend data</span>
            </div>
          </div>

          <div className="landing-hero-visual">
            <div className="landing-orb landing-orb-one" />
            <div className="landing-orb landing-orb-two" />

            <div className="landing-preview">
              <div className="preview-topbar">
                <div className="preview-window-dots">
                  <i />
                  <i />
                  <i />
                </div>
                <span>CTI-BTP / Overview</span>
                <span className="preview-live">
                  <span /> LOCAL
                </span>
              </div>

              <div className="preview-heading">
                <div>
                  <span className="preview-overline">WORKSPACE</span>
                  <h3>Security overview</h3>
                  <p>Threat intelligence at a glance</p>
                </div>
                <span className="preview-shield">
                  <ShieldCheck size={22} />
                </span>
              </div>

              <div className="preview-metrics">
                <div className="preview-metric">
                  <span>CTI Records</span>
                  <Database size={17} />
                  <strong>Live data</strong>
                  <small>From Flask API</small>
                </div>
                <div className="preview-metric">
                  <span>Risk analysis</span>
                  <Activity size={17} />
                  <strong>Risk-aware</strong>
                  <small>Indicator assessment</small>
                </div>
              </div>

              <div className="preview-record">
                <div className="preview-record-heading">
                  <span>THREAT INDICATOR</span>
                  <span>RISK</span>
                </div>
                <div className="preview-record-row">
                  <div className="preview-record-icon">
                    <Globe2 size={17} />
                  </div>
                  <div className="preview-record-name">
                    <strong>Threat intelligence</strong>
                    <span>Structured indicator records</span>
                  </div>
                  <span className="preview-risk-badge">Risk assessed</span>
                </div>
              </div>

              <div className="preview-bottom">
                <div className="preview-bottom-icon">
                  <LockKeyhole size={17} />
                </div>
                <div>
                  <strong>Policy-based access</strong>
                  <span>Organizational context matters</span>
                </div>
                <ArrowUpRight size={17} />
              </div>
            </div>

            <div className="landing-float-card">
              <span className="landing-float-icon">
                <Zap size={17} />
              </span>
              <span>
                <strong>Risk-aware</strong>
                <small>Decision workflow</small>
              </span>
            </div>
          </div>
        </section>

        <section className="landing-principles" aria-label="Platform principles">
          <div>
            <span className="principle-icon"><Network size={19} /></span>
            <span>
              <strong>Cross-organizational</strong>
              <small>Intelligence sharing</small>
            </span>
          </div>
          <div>
            <span className="principle-icon"><Activity size={19} /></span>
            <span>
              <strong>Risk-adaptive</strong>
              <small>Context-aware policies</small>
            </span>
          </div>
          <div>
            <span className="principle-icon"><Fingerprint size={19} /></span>
            <span>
              <strong>Privacy-focused</strong>
              <small>Attribute-based research</small>
            </span>
          </div>
          <div>
            <span className="principle-icon"><Building2 size={19} /></span>
            <span>
              <strong>Organization-aware</strong>
              <small>Policy evaluation</small>
            </span>
          </div>
        </section>

        <section className="landing-section" id="features">
          <div className="landing-section-heading">
            <span className="landing-section-label">PLATFORM CAPABILITIES</span>
            <h2>
              Intelligence sharing,
              <br />
              <span>with context and control.</span>
            </h2>
            <p>
              A research-oriented approach to processing threat data,
              assessing risk, and exploring controlled information sharing.
            </p>
          </div>

          <div className="landing-feature-grid">
            {features.map((feature) => {
              const Icon = feature.icon

              return (
                <article className="landing-feature-card" key={feature.number}>
                  <div className={`landing-feature-icon ${feature.color}`}>
                    <Icon size={23} />
                  </div>
                  <span className="landing-feature-number">
                    {feature.number}
                  </span>
                  <h3>{feature.title}</h3>
                  <p>{feature.description}</p>
                  <a href="#workflow">
                    Explore workflow <ArrowRight size={15} />
                  </a>
                </article>
              )
            })}
          </div>
        </section>

        <section className="landing-workflow-section" id="workflow">
          <div className="landing-workflow-intro">
            <span className="landing-section-label">THE WORKFLOW</span>
            <h2>From raw indicators to informed decisions.</h2>
            <p>
              The project brings intelligence processing and access policy
              evaluation together in a single research workflow.
            </p>
            <button
              className="landing-primary-button"
              onClick={onOpenDashboard}
            >
              View operational dashboard <ArrowRight size={17} />
            </button>
          </div>

          <div className="landing-workflow-list">
            {workflow.map((step, index) => {
              const Icon = step.icon

              return (
                <div className="landing-workflow-item" key={step.title}>
                  <div className="landing-workflow-number">
                    {String(index + 1).padStart(2, '0')}
                  </div>
                  <div className="landing-workflow-icon">
                    <Icon size={21} />
                  </div>
                  <div className="landing-workflow-copy">
                    <h3>{step.title}</h3>
                    <p>{step.description}</p>
                  </div>
                  <ChevronRight className="landing-workflow-arrow" size={18} />
                </div>
              )
            })}
          </div>
        </section>

        <section className="landing-research" id="research">
          <div className="landing-research-icon">
            <ShieldCheck size={27} />
          </div>
          <div className="landing-research-copy">
            <span className="landing-section-label">RESEARCH DIRECTION</span>
            <h2>Privacy-aware intelligence exchange.</h2>
            <p>
              The project investigates how risk-adaptive access policies can
              work alongside attribute-based encryption concepts to support
              controlled sharing between organizations.
            </p>
            <span className="landing-research-disclaimer">
              Cryptographic protection and complete access enforcement remain
              implementation goals, not currently completed guarantees.
            </span>
          </div>
          <button
            className="landing-research-button"
            onClick={onOpenDashboard}
          >
            Open project <ArrowUpRight size={17} />
          </button>
        </section>
      </main>

      <footer className="landing-footer">
        <a className="landing-brand landing-footer-brand" href="#home">
          <span className="landing-brand-icon">
            <ShieldCheck size={20} />
          </span>
          <span className="landing-brand-copy">
            <strong>CTI-BTP</strong>
            <small>THREAT INTELLIGENCE</small>
          </span>
        </a>
        <p>
          Cyber Threat Intelligence Sharing · Research Prototype
        </p>
        <button onClick={onOpenDashboard}>
          Open dashboard <ArrowRight size={15} />
        </button>
      </footer>
    </div>
  )
}

export default LandingPage
