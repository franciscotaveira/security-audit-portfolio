/**
 * OWASP Top 10 Vulnerability Data
 * Complete database with vulnerable and secure code examples
 */

export interface Vulnerability {
  id: number;
  category: string;
  title: string;
  icon: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  cwe: string;
  description: string;
  impact: string;
  vulnerableCode: string;
  secureCode: string;
  exploit: string;
  fix: string;
  testCount: number;
}

export const OWASP_VULNERABILITIES: Vulnerability[] = [
  {
    id: 1,
    category: "A01:2021",
    title: "Broken Access Control",
    icon: "🔓",
    severity: "critical",
    cwe: "CWE-284",
    description: "Failures in access control allow users to act outside their intended permissions, potentially accessing other users' data or admin functions.",
    impact: "Unauthorized access to sensitive data, data modification, or complete system takeover.",
    vulnerableCode: `// ❌ VULNERABLE: No authorization check
app.get('/api/users/:id', async (req, res) => {
  const user = await User.findById(req.params.id);
  res.json(user); // Anyone can access any user!
});

app.post('/api/admin/delete-user', async (req, res) => {
  // No role check - any logged in user can delete!
  await User.deleteOne({ id: req.body.userId });
  res.json({ success: true });
});`,
    secureCode: `// ✅ SECURE: Proper authorization
app.get('/api/users/:id', requireAuth, async (req, res) => {
  // Users can only access their own data
  if (req.user.id !== req.params.id && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden' });
  }
  const user = await User.findById(req.params.id);
  res.json(user);
});

app.post('/api/admin/delete-user', requireAuth, requireAdmin, async (req, res) => {
  // Only admins can reach this endpoint
  await User.deleteOne({ id: req.body.userId });
  auditLog('USER_DELETED', req.user.id, req.body.userId);
  res.json({ success: true });
});`,
    exploit: "An attacker simply changes the user ID in the URL from /api/users/123 to /api/users/456 to access another user's data. No authentication bypass needed - just parameter tampering.",
    fix: "Implement proper authorization checks on every endpoint. Use middleware for role-based access control. Always verify resource ownership before returning data.",
    testCount: 3
  },
  {
    id: 2,
    category: "A02:2021",
    title: "Cryptographic Failures",
    icon: "🔐",
    severity: "critical",
    cwe: "CWE-327",
    description: "Weak cryptographic algorithms or improper implementation expose sensitive data. Includes weak hashing, missing encryption, and poor key management.",
    impact: "Password compromise, data breach, identity theft, regulatory violations.",
    vulnerableCode: `// ❌ VULNERABLE: Weak password hashing
const crypto = require('crypto');

function hashPassword(password) {
  // MD5 is cryptographically broken!
  return crypto.createHash('md5').update(password).digest('hex');
}

// Storing secrets in code
const JWT_SECRET = 'super-secret-123';
const API_KEY = 'sk_live_abcd1234';

// Logging sensitive data
console.log(\`Login: \${email}, password: \${password}\`);`,
    secureCode: `// ✅ SECURE: Strong password hashing
import bcrypt from 'bcrypt';
import crypto from 'crypto';

const SALT_ROUNDS = 12;

async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, SALT_ROUNDS);
}

async function verifyPassword(password: string, hash: string): Promise<boolean> {
  return bcrypt.compare(password, hash);
}

// Secrets from environment
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  throw new Error('JWT_SECRET must be at least 32 characters');
}

// Structured logging without sensitive data
logger.info('Login attempt', { email, timestamp: Date.now() });`,
    exploit: "MD5 hashes can be cracked in seconds using rainbow tables or GPU brute force. Common passwords like 'password123' are instantly compromised.",
    fix: "Use bcrypt, scrypt, or Argon2 for password hashing. Store secrets in environment variables. Never log passwords or tokens. Use minimum 256-bit keys.",
    testCount: 3
  },
  {
    id: 3,
    category: "A03:2021",
    title: "Injection",
    icon: "💉",
    severity: "critical",
    cwe: "CWE-89",
    description: "User-supplied data is sent to an interpreter as part of a command or query. Includes SQL, NoSQL, OS command, and LDAP injection.",
    impact: "Complete database compromise, data exfiltration, remote code execution, full system takeover.",
    vulnerableCode: `// ❌ VULNERABLE: SQL Injection
app.get('/api/users', async (req, res) => {
  const { search } = req.query;
  // Direct string interpolation = SQL Injection!
  const query = \`SELECT * FROM users WHERE name LIKE '%\${search}%'\`;
  const users = await db.query(query);
  res.json(users);
});

// ❌ VULNERABLE: Command Injection
app.post('/api/ping', (req, res) => {
  const { host } = req.body;
  // Direct execution = Command Injection!
  exec(\`ping -c 1 \${host}\`, (err, stdout) => {
    res.send(stdout);
  });
});`,
    secureCode: `// ✅ SECURE: Parameterized Queries
app.get('/api/users', async (req, res) => {
  const { search } = req.query;
  // Use parameterized queries - NEVER interpolate!
  const query = 'SELECT * FROM users WHERE name LIKE $1';
  const users = await db.query(query, [\`%\${search}%\`]);
  res.json(users);
});

// ✅ SECURE: Allowlist + Safe Execution
import { execFile } from 'child_process';
import { isIP } from 'net';

app.post('/api/ping', (req, res) => {
  const { host } = req.body;
  
  // Validate: only allow valid IP addresses
  if (!isIP(host)) {
    return res.status(400).json({ error: 'Invalid IP address' });
  }
  
  // Use execFile instead of exec (no shell)
  execFile('ping', ['-c', '1', host], (err, stdout) => {
    res.send(stdout);
  });
});`,
    exploit: `Attacker sends: search=' OR '1'='1' --
This transforms the query to: SELECT * FROM users WHERE name LIKE '%' OR '1'='1' --%'
Result: Returns ALL users in the database.`,
    fix: "Always use parameterized queries or prepared statements. Use ORMs with proper escaping. For commands, use execFile instead of exec and validate all inputs against an allowlist.",
    testCount: 3
  },
  {
    id: 4,
    category: "A04:2021",
    title: "Insecure Design",
    icon: "📐",
    severity: "high",
    cwe: "CWE-284",
    description: "Security flaws baked into the application's architecture. Missing security controls, threat modeling failures, and insecure patterns.",
    impact: "Fundamental security weaknesses that cannot be fixed with patches alone.",
    vulnerableCode: `// ❌ VULNERABLE: Insecure password reset design
app.post('/api/reset-password', async (req, res) => {
  const { email } = req.body;
  
  // Predictable reset token!
  const resetToken = Date.now().toString();
  
  await User.update({ email }, { resetToken });
  
  // Token never expires!
  await sendEmail(email, \`Reset: /reset?token=\${resetToken}\`);
  
  res.json({ message: 'Email sent' });
});

// ❌ VULNERABLE: Rate limit bypass
// No rate limiting on failed attempts
for (let i = 0; i < 10000; i++) {
  await tryLogin(email, passwords[i]);
}`,
    secureCode: `// ✅ SECURE: Cryptographic reset token with expiry
import crypto from 'crypto';

app.post('/api/reset-password', rateLimit({ max: 3 }), async (req, res) => {
  const { email } = req.body;
  
  // Cryptographically secure token
  const resetToken = crypto.randomBytes(32).toString('hex');
  const hashedToken = crypto.createHash('sha256').update(resetToken).digest('hex');
  
  // Token expires in 15 minutes
  const expiry = new Date(Date.now() + 15 * 60 * 1000);
  
  await User.update({ email }, { 
    resetToken: hashedToken,
    resetTokenExpiry: expiry 
  });
  
  await sendEmail(email, \`Reset: /reset?token=\${resetToken}\`);
  
  // Don't reveal if email exists
  res.json({ message: 'If the email exists, a reset link was sent' });
});`,
    exploit: "An attacker can generate reset tokens by simply guessing timestamps around when they requested a reset. With millisecond precision, there are only ~1000 possibilities per second to try.",
    fix: "Use threat modeling during design. Implement defense in depth. Use secure random token generation. Add expiry to all tokens. Implement rate limiting on sensitive operations.",
    testCount: 3
  },
  {
    id: 5,
    category: "A05:2021",
    title: "Security Misconfiguration",
    icon: "⚙️",
    severity: "high",
    cwe: "CWE-16",
    description: "Insecure default configurations, incomplete setups, open cloud storage, misconfigured HTTP headers, and verbose error messages.",
    impact: "Unauthorized access, information disclosure, and system compromise.",
    vulnerableCode: `// ❌ VULNERABLE: Security Misconfiguration
const express = require('express');
const app = express();

// No security headers!
app.use(cors({ origin: '*' })); // CORS wide open

// Debug mode in production
app.use(errorHandler({ dumpExceptions: true, showStack: true }));

// Default credentials
const adminPassword = 'admin123';

// Unnecessary features enabled
app.get('/debug/env', (req, res) => {
  res.json(process.env); // Exposes all env vars!
});

app.get('/admin/logs', (req, res) => {
  res.sendFile('/var/log/app.log');
});`,
    secureCode: `// ✅ SECURE: Proper Configuration
import express from 'express';
import helmet from 'helmet';
import cors from 'cors';

const app = express();

// Security headers via Helmet
app.use(helmet());
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'"],
  }
}));

// Restrictive CORS
app.use(cors({
  origin: ['https://myapp.com'],
  credentials: true,
}));

// Production error handler - no stack traces
app.use((err, req, res, next) => {
  console.error(err); // Log server-side only
  res.status(500).json({ error: 'Internal server error' });
});

// No debug routes in production
if (process.env.NODE_ENV !== 'production') {
  app.get('/debug/env', requireAdmin, (req, res) => {
    res.json({ nodeEnv: process.env.NODE_ENV });
  });
}`,
    exploit: "Attacker visits /debug/env and retrieves all environment variables including database passwords, API keys, and JWT secrets. Game over.",
    fix: "Use security hardening checklists. Disable debug features in production. Set proper CORS origins. Add security headers (Helmet). Remove default credentials. Audit all exposed endpoints.",
    testCount: 3
  },
  {
    id: 6,
    category: "A06:2021",
    title: "Vulnerable Dependencies",
    icon: "📦",
    severity: "medium",
    cwe: "CWE-1104",
    description: "Using components with known vulnerabilities. Outdated libraries, unpatched frameworks, and unmaintained dependencies.",
    impact: "Full system compromise via known exploits with public proof-of-concept code.",
    vulnerableCode: `// ❌ VULNERABLE package.json
{
  "dependencies": {
    "lodash": "4.17.19",      // CVE-2021-23337: Prototype Pollution
    "minimist": "1.2.5",      // CVE-2021-44906: Prototype Pollution
    "express": "4.17.0",      // Multiple CVEs
    "qs": "6.5.2",            // CVE-2022-24999: Prototype Pollution
    "node-fetch": "2.6.0"     // CVE-2022-0235: SSRF
  }
}

// ❌ VULNERABLE: Dynamic require
const plugin = req.query.plugin;
const module = require(plugin); // Arbitrary code execution!`,
    secureCode: `// ✅ SECURE package.json
{
  "dependencies": {
    "lodash": "^4.17.21",     // Patched
    "minimist": "^1.2.8",     // Patched
    "express": "^4.19.2",     // Latest
    "qs": "^6.12.0"           // Patched
  },
  "scripts": {
    "audit": "npm audit --audit-level=high",
    "update": "npm update && npm audit fix"
  }
}

// ✅ SECURE: Plugin allowlist
const ALLOWED_PLUGINS = ['plugin-a', 'plugin-b', 'plugin-c'];

function loadPlugin(name: string) {
  if (!ALLOWED_PLUGINS.includes(name)) {
    throw new Error(\`Plugin '\${name}' is not allowed\`);
  }
  return require(\`./plugins/\${name}\`);
}`,
    exploit: "CVE-2021-23337 in lodash allows prototype pollution via _.merge(). An attacker sends {\"__proto__\": {\"isAdmin\": true}} which pollutes Object.prototype, making all objects have isAdmin=true.",
    fix: "Run npm audit regularly. Subscribe to security advisories. Use Dependabot or Snyk for automated updates. Maintain an allowlist for dynamic imports. Lock dependency versions.",
    testCount: 3
  },
  {
    id: 7,
    category: "A07:2021",
    title: "Auth & Session Failures",
    icon: "🎫",
    severity: "critical",
    cwe: "CWE-287",
    description: "Broken authentication mechanisms including weak passwords, session fixation, and credential stuffing vulnerabilities.",
    impact: "Account takeover, identity theft, unauthorized access to all user data.",
    vulnerableCode: `// ❌ VULNERABLE: JWT Authentication
const jwt = require('jsonwebtoken');

// Fallback secret = easy to guess!
const SECRET = process.env.JWT_SECRET || '123';

function authMiddleware(req, res, next) {
  const token = req.headers.authorization;
  
  try {
    // Accepts 'none' algorithm attack!
    const decoded = jwt.verify(token, SECRET);
    req.user = decoded;
    req.isAdmin = decoded.role === 'admin'; // Trusts token blindly
    next();
  } catch (e) {
    console.log('JWT Error:', e); // Leaks error details
    res.status(401).json({ error: e.message });
  }
}`,
    secureCode: `// ✅ SECURE: JWT Authentication
import jwt from 'jsonwebtoken';
import { z } from 'zod';

const SECRET = process.env.JWT_SECRET;
if (!SECRET || SECRET.length < 32) {
  throw new Error('JWT_SECRET must be configured with 32+ chars');
}

const PayloadSchema = z.object({
  sub: z.string().uuid(),
  role: z.enum(['user', 'admin']),
  exp: z.number(),
});

async function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  
  if (!token) {
    return res.status(401).json({ error: 'Token required' });
  }
  
  try {
    // Force specific algorithm - blocks 'none' attack
    const decoded = jwt.verify(token, SECRET, { 
      algorithms: ['HS256'] 
    });
    
    // Validate payload structure
    const payload = PayloadSchema.parse(decoded);
    req.user = payload;
    next();
  } catch (e) {
    logger.warn('Auth failed', { ip: req.ip });
    res.status(401).json({ error: 'Invalid token' });
  }
}`,
    exploit: "1. Attacker notices JWT_SECRET falls back to '123'\n2. Creates admin token: jwt.sign({sub:'hacker', role:'admin'}, '123')\n3. Uses token to access admin endpoints\n4. Complete account takeover",
    fix: "Never use fallback secrets. Enforce minimum secret length (32+ chars). Specify allowed algorithms explicitly. Validate token payload with schema. Don't expose error details.",
    testCount: 6
  },
  {
    id: 8,
    category: "A08:2021",
    title: "Data Integrity Failures",
    icon: "📝",
    severity: "high",
    cwe: "CWE-502",
    description: "Code and infrastructure that doesn't protect against integrity violations. Includes insecure deserialization and unverified updates.",
    impact: "Remote code execution, injection attacks, privilege escalation.",
    vulnerableCode: `// ❌ VULNERABLE: Insecure Deserialization
app.post('/api/user/settings', (req, res) => {
  // Directly merging user input into object
  const settings = {};
  Object.assign(settings, req.body); // Prototype pollution!
  
  // Or using eval-like patterns
  const data = JSON.parse(req.body.data);
  eval(data.callback); // Remote Code Execution!
  
  res.json({ settings });
});

// ❌ VULNERABLE: No integrity check on updates
app.get('/update', async (req, res) => {
  const update = await fetch('http://updates.example.com/latest.js');
  eval(await update.text()); // Executes arbitrary code!
});`,
    secureCode: `// ✅ SECURE: Safe Deserialization
import { z } from 'zod';

const SettingsSchema = z.object({
  theme: z.enum(['light', 'dark']),
  notifications: z.boolean(),
  language: z.string().max(5),
}).strict(); // Rejects extra properties

app.post('/api/user/settings', (req, res) => {
  // Validate and sanitize input
  const result = SettingsSchema.safeParse(req.body);
  
  if (!result.success) {
    return res.status(400).json({ errors: result.error.issues });
  }
  
  // Only use validated data
  const settings = result.data;
  res.json({ settings });
});

// ✅ SECURE: Verified updates
import crypto from 'crypto';

async function verifyAndApplyUpdate(update: Buffer, signature: string) {
  const publicKey = fs.readFileSync('./update-key.pub');
  const isValid = crypto.verify('sha256', update, publicKey, 
    Buffer.from(signature, 'base64'));
  
  if (!isValid) throw new Error('Update signature invalid');
  // Apply update only after verification
}`,
    exploit: `Attacker sends: {"__proto__": {"isAdmin": true}}
After Object.assign(), every object in the application inherits isAdmin=true via prototype chain. Attacker now has admin access.`,
    fix: "Use schema validation (Zod, Joi) for all input. Never use Object.assign or spread with untrusted data. Sign and verify all updates. Avoid eval and similar patterns.",
    testCount: 9
  },
  {
    id: 9,
    category: "A09:2021", 
    title: "Logging & Monitoring Failures",
    icon: "📊",
    severity: "medium",
    cwe: "CWE-778",
    description: "Insufficient logging, detection, monitoring, and response. Allows attackers to pivot and persist without detection.",
    impact: "Extended breach duration, inability to detect attacks, no forensic evidence.",
    vulnerableCode: `// ❌ VULNERABLE: Poor Logging Practices

// No logging at all on sensitive operations
app.post('/api/admin/change-role', async (req, res) => {
  await User.update({ id: req.body.userId }, { role: 'admin' });
  res.json({ success: true });
});

// Logging sensitive data!
app.post('/api/login', async (req, res) => {
  console.log(\`Login: \${req.body.email} / \${req.body.password}\`);
  // Passwords in logs = data breach!
});

// No alerting on suspicious activity
let failedAttempts = 0; // Not tracked per user
if (!validPassword) {
  failedAttempts++; // Lost on restart
}`,
    secureCode: `// ✅ SECURE: Comprehensive Logging
import winston from 'winston';

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [
    new winston.transports.File({ filename: 'audit.log' }),
  ],
});

// Audit sensitive operations
app.post('/api/admin/change-role', requireAdmin, async (req, res) => {
  await User.update({ id: req.body.userId }, { role: 'admin' });
  
  logger.info('PRIVILEGE_CHANGE', {
    actor: req.user.id,
    target: req.body.userId,
    newRole: 'admin',
    ip: req.ip,
    timestamp: new Date().toISOString(),
  });
  
  res.json({ success: true });
});

// Track failed logins
app.post('/api/login', async (req, res) => {
  logger.info('LOGIN_ATTEMPT', { email: req.body.email, ip: req.ip });
  
  if (!validPassword) {
    logger.warn('LOGIN_FAILED', { email: req.body.email, ip: req.ip });
    await incrementFailedAttempts(req.body.email);
    
    if (await getFailedAttempts(req.body.email) > 5) {
      await alertSecurityTeam('BRUTE_FORCE_DETECTED', req.body.email);
    }
  }
});`,
    exploit: "Attacker performs 10,000 login attempts without triggering any alerts. Without logging, there's no evidence of the attack. Breach goes undetected for months.",
    fix: "Log all authentication events. Implement centralized logging. Set up alerting for anomalies. Never log passwords or tokens. Retain logs for forensic analysis.",
    testCount: 3
  },
  {
    id: 10,
    category: "A10:2021",
    title: "SSRF",
    icon: "🌐",
    severity: "high",
    cwe: "CWE-918",
    description: "Server-Side Request Forgery occurs when an app fetches a remote resource without validating the user-supplied URL.",
    impact: "Access to internal services, cloud metadata theft, port scanning, remote code execution.",
    vulnerableCode: `// ❌ VULNERABLE: SSRF
app.post('/api/fetch-url', async (req, res) => {
  const { url } = req.body;
  
  // No validation - fetches ANY URL!
  const response = await fetch(url);
  const data = await response.text();
  
  res.send(data);
});

// Attacker sends:
// url: "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
// Returns AWS credentials!

// url: "http://localhost:3000/admin/delete-all"
// Triggers internal admin endpoint!`,
    secureCode: `// ✅ SECURE: Protected from SSRF
import { URL } from 'url';
import dns from 'dns/promises';

const ALLOWED_DOMAINS = ['api.example.com', 'cdn.example.com'];
const BLOCKED_IPS = ['169.254.', '127.', '10.', '192.168.', '172.16.'];

async function isUrlSafe(urlString: string): Promise<boolean> {
  try {
    const url = new URL(urlString);
    
    // Only allow HTTPS
    if (url.protocol !== 'https:') return false;
    
    // Check domain allowlist
    if (!ALLOWED_DOMAINS.includes(url.hostname)) return false;
    
    // Resolve DNS and check for internal IPs
    const addresses = await dns.resolve4(url.hostname);
    for (const ip of addresses) {
      if (BLOCKED_IPS.some(blocked => ip.startsWith(blocked))) {
        return false;
      }
    }
    
    return true;
  } catch {
    return false;
  }
}

app.post('/api/fetch-url', async (req, res) => {
  const { url } = req.body;
  
  if (!await isUrlSafe(url)) {
    return res.status(400).json({ error: 'URL not allowed' });
  }
  
  const response = await fetch(url);
  res.send(await response.text());
});`,
    exploit: "1. Attacker sends URL: http://169.254.169.254/latest/meta-data/iam/security-credentials/\n2. Server fetches internal AWS metadata endpoint\n3. Returns IAM credentials to attacker\n4. Attacker now has access to AWS account",
    fix: "Use domain allowlists. Block internal IP ranges. Resolve DNS and verify IPs. Only allow HTTPS. Disable redirects or validate each hop. Use network segmentation.",
    testCount: 3
  }
];

// Category-based grouping
export const OWASP_CATEGORIES = [
  { id: "access-control", name: "Broken Access Control", count: 1 },
  { id: "cryptography", name: "Cryptographic Failures", count: 1 },
  { id: "injection", name: "Injection", count: 1 },
  { id: "design", name: "Insecure Design", count: 1 },
  { id: "misconfiguration", name: "Security Misconfiguration", count: 1 },
  { id: "dependencies", name: "Vulnerable Dependencies", count: 1 },
  { id: "authentication", name: "Auth Failures", count: 1 },
  { id: "integrity", name: "Data Integrity Failures", count: 1 },
  { id: "logging", name: "Logging Failures", count: 1 },
  { id: "ssrf", name: "SSRF", count: 1 },
];

export function getVulnerabilityById(id: number): Vulnerability | undefined {
  return OWASP_VULNERABILITIES.find(v => v.id === id);
}

export function getTotalTestCount(): number {
  return OWASP_VULNERABILITIES.reduce((sum, v) => sum + v.testCount, 0);
}
