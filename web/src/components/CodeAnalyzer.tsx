import React, { useState } from 'react';

interface AnalysisResult {
    type: 'vulnerability' | 'warning' | 'info';
    title: string;
    description: string;
    line?: number;
    cwe?: string;
}

// Simple pattern-based vulnerability detection
const VULNERABILITY_PATTERNS = [
    {
        pattern: /eval\s*\(/gi,
        type: 'vulnerability' as const,
        title: 'Dangerous eval() usage',
        description: 'eval() can execute arbitrary code. Use safer alternatives like JSON.parse() or specific parsers.',
        cwe: 'CWE-95'
    },
    {
        pattern: /\$\{.*\}.*(?:SELECT|INSERT|UPDATE|DELETE)/gi,
        type: 'vulnerability' as const,
        title: 'Potential SQL Injection',
        description: 'String interpolation in SQL queries can lead to SQL injection. Use parameterized queries.',
        cwe: 'CWE-89'
    },
    {
        pattern: /innerHTML\s*=/gi,
        type: 'vulnerability' as const,
        title: 'XSS via innerHTML',
        description: 'Setting innerHTML with user input can cause XSS. Use textContent or sanitize input.',
        cwe: 'CWE-79'
    },
    {
        pattern: /exec\s*\(/gi,
        type: 'vulnerability' as const,
        title: 'Command Injection Risk',
        description: 'exec() with user input can lead to command injection. Use execFile() with argument array.',
        cwe: 'CWE-78'
    },
    {
        pattern: /createHash\s*\(\s*['"]md5['"]/gi,
        type: 'vulnerability' as const,
        title: 'Weak MD5 Hashing',
        description: 'MD5 is cryptographically broken. Use bcrypt, scrypt, or Argon2 for passwords.',
        cwe: 'CWE-328'
    },
    {
        pattern: /password.*=.*['"][^'"]{1,8}['"]/gi,
        type: 'warning' as const,
        title: 'Hardcoded or Weak Password',
        description: 'Passwords should be stored securely and meet minimum length requirements (12+ chars).',
        cwe: 'CWE-521'
    },
    {
        pattern: /jwt\.verify\s*\([^,]+,\s*[^,]+\s*\)/gi,
        type: 'warning' as const,
        title: 'JWT without Algorithm Restriction',
        description: 'Specify allowed algorithms in jwt.verify() to prevent "none" algorithm attacks.',
        cwe: 'CWE-347'
    },
    {
        pattern: /cors\s*\(\s*\{\s*origin:\s*['"]\*['"]/gi,
        type: 'warning' as const,
        title: 'Open CORS Configuration',
        description: 'CORS with origin "*" allows requests from any domain. Restrict to specific origins.',
        cwe: 'CWE-346'
    },
    {
        pattern: /console\.log\s*\(.*password/gi,
        type: 'vulnerability' as const,
        title: 'Password in Logs',
        description: 'Logging passwords exposes sensitive data. Never log credentials.',
        cwe: 'CWE-532'
    },
    {
        pattern: /Math\.random\s*\(\s*\)/gi,
        type: 'warning' as const,
        title: 'Insecure Random Generation',
        description: 'Math.random() is not cryptographically secure. Use crypto.randomBytes() for tokens.',
        cwe: 'CWE-330'
    },
    {
        pattern: /Object\.assign\s*\(\s*\{\s*\}\s*,\s*req\./gi,
        type: 'vulnerability' as const,
        title: 'Prototype Pollution Risk',
        description: 'Merging user input can lead to prototype pollution. Validate input with Zod/Joi.',
        cwe: 'CWE-1321'
    },
    {
        pattern: /readFileSync|writeFileSync/gi,
        type: 'info' as const,
        title: 'Synchronous File I/O',
        description: 'Sync file operations block the event loop. Consider async alternatives.',
        cwe: 'CWE-400'
    },
    {
        pattern: /:\s*any/gi,
        type: 'info' as const,
        title: 'TypeScript "any" Type',
        description: 'Using "any" bypasses type checking. Use specific types for better security.',
        cwe: ''
    },
];

export const CodeAnalyzer: React.FC = () => {
    const [code, setCode] = useState('');
    const [results, setResults] = useState<AnalysisResult[]>([]);
    const [isAnalyzing, setIsAnalyzing] = useState(false);

    const analyzeCode = () => {
        setIsAnalyzing(true);

        // Simulate async analysis
        setTimeout(() => {
            const foundVulnerabilities: AnalysisResult[] = [];
            const lines = code.split('\n');

            VULNERABILITY_PATTERNS.forEach(({ pattern, type, title, description, cwe }) => {
                lines.forEach((line, index) => {
                    if (pattern.test(line)) {
                        foundVulnerabilities.push({
                            type,
                            title,
                            description,
                            line: index + 1,
                            cwe: cwe || undefined,
                        });
                    }
                    // Reset regex lastIndex for global patterns
                    pattern.lastIndex = 0;
                });
            });

            setResults(foundVulnerabilities);
            setIsAnalyzing(false);
        }, 500);
    };

    const getResultIcon = (type: string) => {
        switch (type) {
            case 'vulnerability': return '🔴';
            case 'warning': return '🟡';
            case 'info': return '🔵';
            default: return '⚪';
        }
    };

    const exampleCode = `// Example vulnerable code - try analyzing this!
const express = require('express');
const jwt = require('jsonwebtoken');

const SECRET = process.env.JWT_SECRET || '123';
const adminPassword = 'admin123';

app.get('/api/users', (req, res) => {
  const query = \`SELECT * FROM users WHERE name = '\${req.query.name}'\`;
  db.query(query);
});

app.post('/api/exec', (req, res) => {
  exec(\`ping \${req.body.host}\`);
});

function hashPassword(pwd) {
  return crypto.createHash('md5').update(pwd).digest('hex');
}

console.log('Login:', email, password);
`;

    return (
        <section className="section" id="analyzer">
            <div className="container">
                <div className="analyzer">
                    <div className="analyzer-header">
                        <h2>
                            <span className="text-gradient">🤖 AI Security Analyzer</span>
                        </h2>
                        <p className="text-muted" style={{ marginTop: '0.5rem' }}>
                            Paste your code below to scan for common security vulnerabilities
                        </p>
                    </div>

                    <div className="analyzer-input">
                        <div>
                            <div style={{
                                display: 'flex',
                                justifyContent: 'space-between',
                                marginBottom: '0.5rem'
                            }}>
                                <label style={{
                                    fontSize: '0.875rem',
                                    fontWeight: '600',
                                    color: 'var(--color-text-secondary)'
                                }}>
                                    Your Code
                                </label>
                                <button
                                    className="btn btn-secondary"
                                    style={{ padding: '0.25rem 0.75rem', fontSize: '0.75rem' }}
                                    onClick={() => setCode(exampleCode)}
                                >
                                    Load Example
                                </button>
                            </div>
                            <textarea
                                className="analyzer-textarea"
                                value={code}
                                onChange={(e) => setCode(e.target.value)}
                                placeholder="Paste your JavaScript/TypeScript code here..."
                            />
                        </div>

                        <div>
                            <label style={{
                                fontSize: '0.875rem',
                                fontWeight: '600',
                                color: 'var(--color-text-secondary)',
                                display: 'block',
                                marginBottom: '0.5rem'
                            }}>
                                Analysis Results
                            </label>
                            <div className="analyzer-results">
                                {isAnalyzing ? (
                                    <div style={{
                                        display: 'flex',
                                        alignItems: 'center',
                                        justifyContent: 'center',
                                        height: '100%',
                                        gap: '1rem'
                                    }}>
                                        <div className="loading-spinner" />
                                        <span>Analyzing code...</span>
                                    </div>
                                ) : results.length > 0 ? (
                                    results.map((result, index) => (
                                        <div key={index} className="vulnerability-item">
                                            <div className="vulnerability-icon">
                                                {getResultIcon(result.type)}
                                            </div>
                                            <div className="vulnerability-content">
                                                <div className="vulnerability-title">
                                                    {result.title}
                                                    {result.line && (
                                                        <span style={{
                                                            marginLeft: '0.5rem',
                                                            fontSize: '0.75rem',
                                                            color: 'var(--color-text-muted)'
                                                        }}>
                                                            Line {result.line}
                                                        </span>
                                                    )}
                                                </div>
                                                <div className="vulnerability-description">
                                                    {result.description}
                                                </div>
                                                {result.cwe && (
                                                    <span className="badge badge-purple" style={{ marginTop: '0.5rem' }}>
                                                        {result.cwe}
                                                    </span>
                                                )}
                                            </div>
                                        </div>
                                    ))
                                ) : code.length > 0 ? (
                                    <div style={{
                                        display: 'flex',
                                        flexDirection: 'column',
                                        alignItems: 'center',
                                        justifyContent: 'center',
                                        height: '100%',
                                        color: 'var(--color-accent-tertiary)'
                                    }}>
                                        <span style={{ fontSize: '3rem', marginBottom: '1rem' }}>✅</span>
                                        <span style={{ fontWeight: '600' }}>No vulnerabilities detected!</span>
                                        <span style={{
                                            fontSize: '0.875rem',
                                            color: 'var(--color-text-muted)',
                                            marginTop: '0.5rem'
                                        }}>
                                            Your code looks secure (basic scan)
                                        </span>
                                    </div>
                                ) : (
                                    <div style={{
                                        display: 'flex',
                                        flexDirection: 'column',
                                        alignItems: 'center',
                                        justifyContent: 'center',
                                        height: '100%',
                                        color: 'var(--color-text-muted)'
                                    }}>
                                        <span style={{ fontSize: '3rem', marginBottom: '1rem' }}>📝</span>
                                        <span>Paste code and click "Analyze" to scan</span>
                                    </div>
                                )}
                            </div>
                        </div>
                    </div>

                    <div className="analyzer-actions">
                        <button
                            className="btn btn-primary"
                            onClick={analyzeCode}
                            disabled={!code.trim() || isAnalyzing}
                            style={{ minWidth: '200px' }}
                        >
                            {isAnalyzing ? (
                                <>
                                    <div className="loading-spinner" />
                                    Analyzing...
                                </>
                            ) : (
                                <>
                                    <span>🔍</span>
                                    Analyze Code
                                </>
                            )}
                        </button>
                    </div>

                    <div style={{
                        marginTop: '2rem',
                        textAlign: 'center',
                        color: 'var(--color-text-muted)',
                        fontSize: '0.75rem'
                    }}>
                        💡 This is a basic pattern-based scanner. For comprehensive security audits,
                        consider tools like Snyk, SonarQube, or professional penetration testing.
                    </div>
                </div>
            </div>
        </section>
    );
};

export default CodeAnalyzer;
