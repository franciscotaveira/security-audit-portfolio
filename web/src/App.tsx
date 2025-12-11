import { useState, useEffect } from 'react';
import Editor, { DiffEditor, useMonaco } from '@monaco-editor/react';
import { ClerkProvider, SignedIn, SignedOut, SignInButton, UserButton, useUser } from "@clerk/clerk-react";
import './index.css';
import './landing.css';

// ============================================================================
// CONFIG
// ============================================================================
// Substitua pela sua Publishable Key do Clerk Dashboard
const CLERK_PUBLISHABLE_KEY = import.meta.env.VITE_CLERK_PUBLISHABLE_KEY || "pk_test_ExemploDeChavePublicaDoClerkAqui";

if (!import.meta.env.VITE_CLERK_PUBLISHABLE_KEY) {
  console.warn("⚠️ Clerk Key not found in .env. Configure VITE_CLERK_PUBLISHABLE_KEY");
}

// ============================================================================
// TYPES
// ============================================================================
interface Vulnerability {
  severity: 'critical' | 'high' | 'medium' | 'low';
  title: string;
  line?: number;
  cwe?: string;
  fix: string;
}

type AnalysisMode = 'security' | 'performance' | 'clean-code' | 'qa' | 'architect' | 'docs';

interface AnalysisResult {
  vulnerabilities: Vulnerability[];
  score: number;
  aiAnalysis?: string;
  fixedCode?: string; // Novo: Código corrigido pela IA
  mode?: AnalysisMode;
}

// ============================================================================
// CONSTANTS
// ============================================================================
// const FREE_LIMIT_ANALYSES = 5;
// const FREE_LIMIT_CHARS = 1000;
// const PRO_PRICE = 29;
const DONATION_LINK = 'https://buy.stripe.com/test_8x29AU5sgccu8LM9skfUQ01'; // Replace with your real donation link

// ============================================================================
// MODES & PROMPTS
// ============================================================================
const MODES: Record<AnalysisMode, { label: string; icon: string; prompt: string }> = {
  security: {
    label: 'Elite Security Officer',
    icon: '👮‍♂️',
    prompt: 'You are an Elite Cybersecurity Officer (NSA-Level). Execute a deep "Chain of Thought" analysis: 1. Map the entire data flow (inputs/outputs). 2. Identify obscure attack vectors (Race Conditions, Prototype Pollution, Timing Attacks). 3. Mentally simulate the intrusion. 4. Generate the bulletproof code. Return JSON: { "analysis": "Detailed technical report...", "fixedCode": "Secure code" }.'
  },
  performance: {
    label: 'Performance Guru',
    icon: '⚡',
    prompt: 'You are a High Performance Engineer (HFT - High Frequency Trading). Your goal is zero latency. 1. Identify Big O complexity. 2. Find unnecessary memory allocations. 3. Eliminate re-renders. 4. Rewrite for maximum speed. Return JSON: { "analysis": "Bottleneck analysis...", "fixedCode": "Optimized code" }.'
  },
  'clean-code': {
    label: 'Clean Code Arch',
    icon: '🧹',
    prompt: 'You are the embodiment of Clean Code. 1. Analyze cognitive readability. 2. Identify SOLID and DRY violations. 3. Simplify logic so a child could understand. 4. Apply perfect semantic naming. Return JSON: { "analysis": "Design critique...", "fixedCode": "Code artwork" }.'
  },
  qa: {
    label: 'Test Automation AI',
    icon: '🧪',
    prompt: 'You are an AI specialized in breaking code. 1. Analyze all execution paths (branches). 2. Identify extreme Edge Cases (null, overflow, wrong types). 3. Write a test suite (Jest/Vitest) that guarantees 100% real coverage. Return JSON: { "analysis": "Coverage strategy...", "fixedCode": "Complete test suite" }.'
  },
  architect: {
    label: 'Principal Architect',
    icon: '🏛️',
    prompt: 'You are a Principal Architect at a Big Tech. 1. Evaluate horizontal scalability and maintainability. 2. Critique coupling and cohesion. 3. Propose Enterprise Design Patterns (Adapter, Factory, Observer) if applicable. Return JSON: { "analysis": "Architectural review...", "fixedCode": "Refactored structure" }.'
  },
  docs: {
    label: 'Doc Master',
    icon: '📚',
    prompt: 'You are a Senior Technical Writer. Generate world-class documentation. 1. Create an executive summary. 2. Generate detailed JSDoc/TSDoc for every signature. 3. Create practical usage examples. Return JSON: { "analysis": "Overview...", "fixedCode": "100% documented code" }.'
  }
};

/* const PATTERNS = [
  { pattern: /eval\s*\(/gi, severity: 'critical' as const, title: 'Code Injection', fix: 'Avoid eval()' },
  { pattern: /\$\{.*\}.*SELECT/gi, severity: 'critical' as const, title: 'SQL Injection', fix: 'Use parameters' },
  // ... (simplificado para brevidade, padrões regex ainda rodam no free)
]; */

// ============================================================================
// LOGIC
// ============================================================================
function analyzeCodePatterns(code: string) {
  // Simulação rápida para o plano Free (Regex)
  // Em produção, aqui iriam todos os regex do arquivo anterior
  const score = code.includes('eval') || code.includes('SELECT') ? 50 : 100;
  return { vulnerabilities: [], score };
}

async function analyzeWithAI(code: string, apiKey: string, mode: AnalysisMode): Promise<{ analysis: string, fixedCode: string }> {
  const modeConfig = MODES[mode];

  const response = await fetch('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${apiKey}` },
    body: JSON.stringify({
      model: 'gpt-4o', // Usando modelo mais forte se available, ou fallback
      messages: [
        { role: 'system', content: modeConfig.prompt + ' Reply ONLY valid JSON.' },
        { role: 'user', content: code }
      ],
      response_format: { type: "json_object" }, // Garante JSON
      temperature: 0.2
    })
  });

  if (!response.ok) throw new Error('AI Failure');
  const data = await response.json();
  const content = data.choices[0]?.message?.content;
  return JSON.parse(content);
}

// ============================================================================
// APP Component - Landing
// ============================================================================
function LandingPage() {
  return (
    <div className="landing">
      <nav className="landing-nav">
        <div className="brand">🧠 Security Brain <span className="beta-tag">AI</span></div>
        <SignInButton mode="modal">
          <button className="btn-text">Sign In</button>
        </SignInButton>
      </nav>

      <section className="hero">
        <div className="hero-content">
          <h1>The World's First <span className="text-gradient">Self-Healing IDE</span>.</h1>
          <p className="hero-sub">
            Let 6 Elite Agents (Security, Performance, Architecture) fix your code while you watch.
            Secure and encrypted login.
          </p>

          <div className="auth-buttons">
            <SignInButton mode="modal">
              <button className="btn-cta">Sign Up with Google / Email &rarr;</button>
            </SignInButton>
          </div>
          <p className="hero-obs">Secure access via Clerk • No credit card required</p>
        </div>

        <div className="hero-visual">
          <div className="visual-card">
            <div className="visual-header">
              <span className="dot red"></span><span className="dot yellow"></span><span className="dot green"></span>
            </div>
            <div className="visual-code">
              <div className="code-line"><span className="kw">function</span> <span className="fn">transfer</span>() {'{'}</div>
              <div className="code-line indent error-line">  <span className="var">db</span>.query(<span className="str">`SELECT * FROM users...`</span>);</div>
              <div className="code-line indent correction">  <span className="comment">// ✨ Auto-fix: Parameterized Query applied</span></div>
              <div className="code-line">{'}'}</div>
            </div>
          </div>
        </div>
      </section>

      <section className="features-grid">
        <div className="feature-card">
          <span className="icon">👮‍♂️</span>
          <h3>Security Officer</h3>
          <p>Detects and fixes OWASP Top 10 flaws, injections, and critical logic failures.</p>
        </div>
        <div className="feature-card">
          <span className="icon">⚡</span>
          <h3>Performance Guru</h3>
          <p>Optimizes O(n²) algorithms, reduces renders, and eliminates memory bottlenecks.</p>
        </div>
        <div className="feature-card">
          <span className="icon">🧪</span>
          <h3>QA Engineer</h3>
          <p>Writes complete unit tests (Jest/Vitest) to cover your edge-cases.</p>
        </div>
      </section>

      <footer className="landing-footer">
        <div className="footer-content">
          <span>&copy; 2024 Security Brain Inc. All rights reserved.</span>
        </div>
      </footer>
    </div>
  );
}

// ============================================================================
// IDE COMPONENT (Protected)
// ============================================================================
function IDE() {
  const { user } = useUser();
  // const { openUserProfile } = useClerk();

  const [code, setCode] = useState('// Paste your code here for analysis...');
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);

  // Local state for app config (API Key, usage) - could be moved to DB later
  const [openaiKey, setOpenaiKey] = useState(() => localStorage.getItem('sb_openai_key') || '');
  const [activeTab, setActiveTab] = useState<'editor' | 'diff'>('editor');
  const [mode, setMode] = useState<AnalysisMode>('security');
  const [showSettings, setShowSettings] = useState(false);
  const [showUpgrade, setShowUpgrade] = useState(false);

  // Default isPro check (mocked for now, integrate with custom claims later)
  // const isPro = false; // TODO: Check Stripe subscription via Clerk metadata
  // const analysesUsed = 0; // TODO: Track in DB

  const monaco = useMonaco();

  useEffect(() => {
    if (monaco) {
      // @ts-ignore
      monaco.languages.typescript.javascriptDefaults.setDiagnosticsOptions({ noSemanticValidation: true, noSyntaxValidation: false });
    }
  }, [monaco]);

  const handleAnalyze = async () => {
    if (!code.trim() || code.includes('// Cole seu código')) return;
    setIsAnalyzing(true);
    setResult(null);
    setActiveTab('editor');

    const patterns = analyzeCodePatterns(code);
    let aiResponse = { analysis: '', fixedCode: '' };

    if (openaiKey) {
      try {
        aiResponse = await analyzeWithAI(code, openaiKey, mode);
      } catch (e) {
        aiResponse.analysis = 'AI Analysis Error. Check your key.';
      }
    } else {
      aiResponse.analysis = "Demo Mode. Add your OpenAI Key for deep analysis.";
      aiResponse.fixedCode = "// Auto-fix requires OpenAI Key.";
    }

    setResult({
      vulnerabilities: patterns.vulnerabilities,
      score: patterns.score,
      aiAnalysis: aiResponse.analysis,
      fixedCode: aiResponse.fixedCode,
      mode
    });
    setIsAnalyzing(false);

    if (openaiKey && aiResponse.fixedCode) setActiveTab('diff');
  };

  const applyFix = () => {
    if (result?.fixedCode) {
      setCode(result.fixedCode);
      setActiveTab('editor');
      setResult(null);
    }
  };

  const saveKey = (key: string) => {
    setOpenaiKey(key);
    localStorage.setItem('sb_openai_key', key);
    setShowSettings(false);
  };

  return (
    <div className="app">
      <header className="header">
        <div className="brand">🧠 <span>Security Brain</span> <span className="beta-tag">BETA</span></div>
        <div className="header-right">
          <button className="btn-icon" onClick={() => setShowSettings(true)}>{openaiKey ? '🤖 Key Configured' : '⚙️ Config Key'}</button>

          <div className="user-info">
            <button className="upgrade-btn-small" onClick={() => setShowUpgrade(true)}>💝 Support Us</button>
            {/* Clerk User Button */}
            <UserButton afterSignOutUrl="/" />
          </div>
        </div>
      </header>

      <main className="main-ide">
        <div className="ide-container">
          <div className="ide-toolbar">
            <div className="modes">
              {(Object.keys(MODES) as AnalysisMode[]).map((m) => (
                <button key={m} className={`mode-pill ${mode === m ? 'active' : ''}`} onClick={() => setMode(m)}>
                  {MODES[m].icon} {MODES[m].label}
                </button>
              ))}
            </div>
            <div className="actions">
              <button className="btn-run" onClick={handleAnalyze} disabled={isAnalyzing}>
                {isAnalyzing ? 'Thinking...' : '▶ Run Analysis'}
              </button>
            </div>
          </div>

          <div className="editor-wrapper">
            {result?.fixedCode && (
              <div className="diff-tabs">
                <button className={activeTab === 'editor' ? 'active' : ''} onClick={() => setActiveTab('editor')}>Editor</button>
                <button className={activeTab === 'diff' ? 'active' : ''} onClick={() => setActiveTab('diff')}>✨ Fix Preview</button>
              </div>
            )}

            {activeTab === 'editor' ? (
              <Editor height="65vh" defaultLanguage="javascript" value={code} onChange={(val) => setCode(val || '')} theme="vs-dark" options={{ minimap: { enabled: false }, fontSize: 14, padding: { top: 20 }, scrollBeyondLastLine: false }} />
            ) : (
              <div className="diff-container">
                <DiffEditor height="60vh" original={code} modified={result?.fixedCode} language="javascript" theme="vs-dark" options={{ readOnly: true, renderSideBySide: true }} />
                <div className="diff-actions"><button className="btn-apply" onClick={applyFix}>✨ Accept & Fix</button></div>
              </div>
            )}
          </div>

          {result && (
            <div className="analysis-panel">
              <div className="panel-header">
                <h3>🔍 {MODES[mode].label} Analysis</h3>
                <div className={`score-badge ${result.score >= 80 ? 'good' : 'bad'}`}>Health: {result.score}%</div>
              </div>
              <div className="ai-markdown">{result.aiAnalysis}</div>
            </div>
          )}
        </div>
      </main>

      {showSettings && (
        <div className="modal-bg" onClick={() => setShowSettings(false)}>
          <div className="modal" onClick={e => e.stopPropagation()}>
            <h2>🤖 Configure OpenAI</h2>
            <p style={{ fontSize: '0.9rem', color: '#888', marginBottom: '1rem' }}>
              Add your API Key to unlock the full power of the AI Agents.
              <br />Your key is saved <strong>locally</strong> in your browser.
            </p>
            <form onSubmit={e => { e.preventDefault(); saveKey((e.target as any).key.value); }}>
              <input type="password" name="key" placeholder="sk-..." className="input" defaultValue={openaiKey} />
              <button className="btn-primary">Save Key</button>
            </form>
            <button className="close" onClick={() => setShowSettings(false)}>✕</button>
          </div>
        </div>
      )}

      {showUpgrade && (
        <div className="modal-bg" onClick={() => setShowUpgrade(false)}>
          <div className="modal" onClick={e => e.stopPropagation()}>
            <h2>💝 Support the Project</h2>
            <p style={{ color: '#888', margin: '1rem 0' }}>
              Security Brain is open for everyone.
              <br />If this tool helps you, consider supporting its development!
            </p>
            <button className="btn-primary" onClick={() => window.open(`${DONATION_LINK}?prefilled_email=${user?.primaryEmailAddress?.emailAddress}`, '_blank')}>
              Donate & Support 🚀
            </button>
            <button className="close" onClick={() => setShowUpgrade(false)}>✕</button>
          </div>
        </div>
      )}
    </div>
  );
}

// ============================================================================
// ROOT APP
// ============================================================================
export default function App() {
  return (
    <ClerkProvider publishableKey={CLERK_PUBLISHABLE_KEY} afterSignOutUrl="/">
      <SignedOut>
        <LandingPage />
      </SignedOut>
      <SignedIn>
        <IDE />
      </SignedIn>
    </ClerkProvider>
  );
}
