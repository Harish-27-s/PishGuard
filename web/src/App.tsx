import { useState } from 'react'

type Verdict = 'Safe' | 'Suspicious' | 'Dangerous'

interface CheckResult {
  verdict: Verdict
  score: number
  reasons: string[]
  source: string
}

const API_BASE = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'

const DEMO_CASES: { label: string; input: string; hint: string }[] = [
  {
    label: '1. Known phishing URL (DB hit)',
    input: 'http://onlinesbii.co.in/netbanking',
    hint: 'Lookalike that may also hit rules if not yet in DB',
  },
  {
    label: '2. Bank / gov lookalike',
    input: 'http://sbi-kyc-verification.top/login.php',
    hint: 'Suspicious TLD + brand impersonation',
  },
  {
    label: '3. Fake e-challan + APK',
    input:
      'Traffic Police Notice: Your vehicle challan of Rs 1500 is pending. Pay immediately: http://echallan-notice.com/download/echallan.apk',
    hint: 'Message with malicious .apk link',
  },
  {
    label: '4. Hindi KYC scam message',
    input:
      'प्रिय ग्राहक, आपका बैंक खाता आज रात ब्लॉक कर दिया जाएगा। तुरंत अपना पैन कार्ड और आधार अपडेट करें http://bank-kyc-verify.top',
    hint: 'Hindi urgency + lookalike domain',
  },
  {
    label: '5. Genuine site (Safe)',
    input: 'https://irctc.co.in/',
    hint: 'Official IRCTC – should score Safe',
  },
]

function verdictColor(v: Verdict): { color: string; bg: string } {
  if (v === 'Safe') return { color: 'var(--safe)', bg: 'var(--safe-bg)' }
  if (v === 'Suspicious') return { color: 'var(--suspicious)', bg: 'var(--suspicious-bg)' }
  return { color: 'var(--dangerous)', bg: 'var(--dangerous-bg)' }
}

export default function App() {
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<CheckResult | null>(null)

  async function handleCheck() {
    const text = input.trim()
    if (!text) {
      setError('Please paste a URL or message.')
      setResult(null)
      return
    }
    setLoading(true)
    setError(null)
    setResult(null)
    try {
      const res = await fetch(`${API_BASE}/check`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ input: text }),
      })
      if (!res.ok) {
        const body = await res.json().catch(() => ({}))
        throw new Error(body.detail || `Request failed (${res.status})`)
      }
      const data: CheckResult = await res.json()
      setResult(data)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Network or server error')
    } finally {
      setLoading(false)
    }
  }

  function loadDemo(demoInput: string) {
    setInput(demoInput)
    setError(null)
    setResult(null)
  }

  return (
    <div style={styles.page}>
      <header style={styles.header}>
        <h1 style={styles.title}>PhishGuard</h1>
        <p style={styles.subtitle}>
          Explainable phishing & domain-spoofing detection for Indian citizens
        </p>
      </header>

      <main style={styles.main}>
        <section style={styles.card}>
          <label htmlFor="input" style={styles.label}>
            Paste a URL or a text message
          </label>
          <textarea
            id="input"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="https://example.com or SMS / WhatsApp message text…"
            rows={5}
            style={styles.textarea}
            disabled={loading}
          />
          <div style={styles.actions}>
            <button
              type="button"
              onClick={handleCheck}
              disabled={loading}
              style={{
                ...styles.checkBtn,
                opacity: loading ? 0.7 : 1,
              }}
            >
              {loading ? 'Checking…' : 'Check'}
            </button>
          </div>
        </section>

        <section style={styles.demoSection}>
          <p style={styles.demoTitle}>One-click demo cases</p>
          <div style={styles.demoGrid}>
            {DEMO_CASES.map((d) => (
              <button
                key={d.label}
                type="button"
                onClick={() => loadDemo(d.input)}
                disabled={loading}
                style={styles.demoBtn}
                title={d.hint}
              >
                {d.label}
              </button>
            ))}
          </div>
        </section>

        {error && (
          <div style={styles.errorBox} role="alert">
            {error}
          </div>
        )}

        {loading && (
          <div style={styles.loadingBox}>
            <div style={styles.spinner} />
            <span>Analysing…</span>
          </div>
        )}

        {result && !loading && (
          <ResultCard result={result} />
        )}
      </main>

      <footer style={styles.footer}>
        API: <code style={styles.code}>{API_BASE}</code>
        {' · '}Seva First Innovation Challenge
      </footer>
    </div>
  )
}

function ResultCard({ result }: { result: CheckResult }) {
  const { color, bg } = verdictColor(result.verdict)
  return (
    <section
      style={{
        ...styles.resultCard,
        borderColor: color,
        background: bg,
      }}
      aria-live="polite"
    >
      <div style={styles.resultHeader}>
        <span style={{ ...styles.verdictBadge, color, borderColor: color }}>
          {result.verdict}
        </span>
        <span style={styles.score}>
          Score: <strong>{result.score}</strong> / 100
        </span>
      </div>
      <p style={styles.source}>Source: {result.source}</p>
      <ul style={styles.reasons}>
        {result.reasons.map((r, i) => (
          <li key={i}>{r}</li>
        ))}
      </ul>
    </section>
  )
}

const styles: Record<string, React.CSSProperties> = {
  page: {
    width: '100%',
    maxWidth: 640,
    display: 'flex',
    flexDirection: 'column',
    gap: '1.5rem',
  },
  header: {
    textAlign: 'center',
  },
  title: {
    fontSize: '1.75rem',
    fontWeight: 700,
    letterSpacing: '-0.02em',
  },
  subtitle: {
    color: 'var(--muted)',
    fontSize: '0.95rem',
    marginTop: '0.35rem',
  },
  main: {
    display: 'flex',
    flexDirection: 'column',
    gap: '1.25rem',
  },
  card: {
    background: 'var(--surface)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius)',
    padding: '1.25rem',
  },
  label: {
    display: 'block',
    fontSize: '0.875rem',
    fontWeight: 500,
    marginBottom: '0.5rem',
    color: 'var(--muted)',
  },
  textarea: {
    width: '100%',
    resize: 'vertical',
    background: 'var(--bg)',
    border: '1px solid var(--border)',
    borderRadius: 8,
    color: 'var(--text)',
    padding: '0.75rem 1rem',
    fontSize: '0.95rem',
    lineHeight: 1.5,
  },
  actions: {
    marginTop: '0.85rem',
    display: 'flex',
    justifyContent: 'flex-end',
  },
  checkBtn: {
    background: 'var(--accent)',
    color: '#fff',
    fontWeight: 600,
    fontSize: '0.95rem',
    padding: '0.6rem 1.5rem',
    borderRadius: 8,
  },
  demoSection: {},
  demoTitle: {
    fontSize: '0.8rem',
    fontWeight: 600,
    color: 'var(--muted)',
    textTransform: 'uppercase',
    letterSpacing: '0.04em',
    marginBottom: '0.6rem',
  },
  demoGrid: {
    display: 'flex',
    flexDirection: 'column',
    gap: '0.4rem',
  },
  demoBtn: {
    textAlign: 'left',
    background: 'var(--surface)',
    border: '1px solid var(--border)',
    color: 'var(--text)',
    padding: '0.55rem 0.85rem',
    borderRadius: 8,
    fontSize: '0.85rem',
  },
  errorBox: {
    background: 'var(--dangerous-bg)',
    border: '1px solid var(--dangerous)',
    color: 'var(--dangerous)',
    padding: '0.75rem 1rem',
    borderRadius: 8,
    fontSize: '0.9rem',
  },
  loadingBox: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.75rem',
    color: 'var(--muted)',
    fontSize: '0.9rem',
  },
  spinner: {
    width: 18,
    height: 18,
    border: '2px solid var(--border)',
    borderTopColor: 'var(--accent)',
    borderRadius: '50%',
    animation: 'spin 0.7s linear infinite',
  },
  resultCard: {
    border: '2px solid',
    borderRadius: 'var(--radius)',
    padding: '1.25rem',
  },
  resultHeader: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    gap: '1rem',
    flexWrap: 'wrap',
  },
  verdictBadge: {
    fontWeight: 700,
    fontSize: '1.1rem',
    padding: '0.25rem 0.75rem',
    borderRadius: 6,
    border: '1.5px solid',
  },
  score: {
    fontSize: '0.95rem',
    color: 'var(--muted)',
  },
  source: {
    fontSize: '0.8rem',
    color: 'var(--muted)',
    marginTop: '0.4rem',
  },
  reasons: {
    marginTop: '0.85rem',
    paddingLeft: '1.2rem',
    fontSize: '0.9rem',
    display: 'flex',
    flexDirection: 'column',
    gap: '0.35rem',
  },
  footer: {
    textAlign: 'center',
    fontSize: '0.75rem',
    color: 'var(--muted)',
    marginTop: 'auto',
    paddingTop: '1rem',
  },
  code: {
    background: 'var(--surface)',
    padding: '0.1rem 0.35rem',
    borderRadius: 4,
    fontSize: '0.75rem',
  },
}

// Inject keyframes for spinner
const styleSheet = document.createElement('style')
styleSheet.textContent = `@keyframes spin { to { transform: rotate(360deg); } }`
document.head.appendChild(styleSheet)
