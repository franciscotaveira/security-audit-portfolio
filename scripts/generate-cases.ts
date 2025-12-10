/**
 * 🔄 AUTOMATED CASE GENERATOR v2
 * Gera 10 novos cases de segurança por dia baseados em CVEs reais
 * 45+ templates totais
 */

import fs from "fs";

// ============================================================================
// TEMPLATES DE VULNERABILIDADES (45+)
// ============================================================================

const TEMPLATES = [
  // CVE-2024-43796: XSS em res.redirect() do Express
  {
    category: "xss",
    name: "Express res.redirect XSS",
    cve: "CVE-2024-43796",
    vuln: `app.get("/redirect", (req, res) => { res.redirect(req.query.url); });`,
    fix: `const url = new URL(req.query.url); if (!ALLOWED_HOSTS.includes(url.hostname)) return res.redirect("/");`
  },
  // CVE-2024-45590: DoS no body-parser
  {
    category: "dos",
    name: "Body-parser DoS",
    cve: "CVE-2024-45590",
    vuln: `app.use(bodyParser.urlencoded({ extended: true })); // Sem limite`,
    fix: `app.use(bodyParser.urlencoded({ extended: true, limit: "1kb", parameterLimit: 10 }));`
  },
  // CVE-2024-29041: Open Redirect
  {
    category: "redirect",
    name: "Express Open Redirect",
    cve: "CVE-2024-29041",
    vuln: `res.location(req.query.next); res.status(302).end();`,
    fix: `const next = req.query.next; if (next.startsWith("/") && !next.startsWith("//")) res.redirect(next);`
  },
  // CVE-2023-44487: HTTP/2 Rapid Reset
  {
    category: "dos",
    name: "HTTP2 Rapid Reset DoS",
    cve: "CVE-2023-44487",
    vuln: `const server = http2.createSecureServer({}); // Sem limite de streams`,
    fix: `const server = http2.createSecureServer({ peerMaxConcurrentStreams: 100 });`
  },
  // CVE-2021-23337: Prototype Pollution
  {
    category: "prototype-pollution",
    name: "Lodash Merge Pollution",
    cve: "CVE-2021-23337",
    vuln: `_.merge(settings, userInput); // Aceita __proto__`,
    fix: `const validated = SettingsSchema.parse(userInput); // Zod validation`
  },
  // CWE-1333: ReDoS
  {
    category: "redos",
    name: "Email Regex ReDoS",
    cve: "CWE-1333",
    vuln: `const EMAIL = /^([a-zA-Z0-9_\\-\\.]+)@((\\[[0-9]{1,3}\\.)|(([a-zA-Z0-9\\-]+\\.)+))([a-zA-Z]{2,4})$/;`,
    fix: `const EMAIL = /^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/; // Regex linear simples`
  },
  // CWE-502: Insecure Deserialization
  {
    category: "deserialization",
    name: "JSON Parse No Validation",
    cve: "CWE-502",
    vuln: `const data = JSON.parse(jsonString); // Aceita qualquer estrutura`,
    fix: `const data = UserSchema.parse(JSON.parse(jsonString)); // Valida com Zod`
  },
  // CWE-798: Hardcoded Credentials
  {
    category: "credentials",
    name: "Hardcoded API Key",
    cve: "CWE-798",
    vuln: `const config = { apiKey: "sk-1234567890" };`,
    fix: `const config = { apiKey: process.env.API_KEY! };`
  },
  // CWE-89: SQL Injection
  {
    category: "sqli",
    name: "SQL Injection Template",
    cve: "CWE-89",
    vuln: "const query = `SELECT * FROM users WHERE id = '${userId}'`;",
    fix: `const query = "SELECT * FROM users WHERE id = $1"; db.query(query, [userId]);`
  },
  // CWE-22: Path Traversal
  {
    category: "path-traversal",
    name: "Path Traversal File Read",
    cve: "CWE-22",
    vuln: `fs.readFileSync("./uploads/" + filename);`,
    fix: `const safe = path.basename(filename); fs.readFileSync(path.join(uploadsDir, safe));`
  },
  // CWE-352: CSRF
  {
    category: "csrf",
    name: "Missing CSRF Token",
    cve: "CWE-352",
    vuln: `app.post("/transfer", (req, res) => { /* sem csrf */ });`,
    fix: `app.post("/transfer", csrfProtection, (req, res) => { /* com csrf */ });`
  },
  // CWE-284: IDOR
  {
    category: "idor",
    name: "IDOR Document Access",
    cve: "CWE-284",
    vuln: `const doc = await Document.findById(req.params.id); res.json(doc);`,
    fix: `if (doc.ownerId !== req.user.id) return res.status(403).json({ error: "Forbidden" });`
  },
  // CWE-915: Mass Assignment
  {
    category: "mass-assignment",
    name: "Mass Assignment Role",
    cve: "CWE-915",
    vuln: `await User.findByIdAndUpdate(id, req.body); // Aceita role: admin`,
    fix: `const updates = pick(req.body, ["name", "email"]); // Whitelist`
  },
  // CWE-1004: Insecure Cookie
  {
    category: "cookie",
    name: "Cookie Without HttpOnly",
    cve: "CWE-1004",
    vuln: `res.cookie("session", token);`,
    fix: `res.cookie("session", token, { httpOnly: true, secure: true, sameSite: "strict" });`
  },
  // CWE-347: JWT None Algorithm
  {
    category: "jwt",
    name: "JWT None Algorithm",
    cve: "CWE-347",
    vuln: `jwt.verify(token, secret); // Aceita alg: none`,
    fix: `jwt.verify(token, secret, { algorithms: ["HS256"] });`
  },
  // CWE-328: Weak Password Hash
  {
    category: "crypto",
    name: "MD5 Password Hash",
    cve: "CWE-328",
    vuln: `crypto.createHash("md5").update(password).digest("hex");`,
    fix: `await bcrypt.hash(password, 12);`
  },
  // CWE-209: Stack Trace Leak
  {
    category: "error",
    name: "Stack Trace Disclosure",
    cve: "CWE-209",
    vuln: `res.status(500).json({ error: err.message, stack: err.stack });`,
    fix: `res.status(500).json({ error: "Internal error" }); // Log interno apenas`
  },
  // CWE-942: CORS Wildcard
  {
    category: "cors",
    name: "CORS Allow All Origins",
    cve: "CWE-942",
    vuln: `app.use(cors({ origin: "*", credentials: true }));`,
    fix: `app.use(cors({ origin: ALLOWED_ORIGINS, credentials: true }));`
  },
  // CWE-78: Command Injection
  {
    category: "command-injection",
    name: "OS Command Injection",
    cve: "CWE-78",
    vuln: "exec(`ping -c 1 ${host}`);",
    fix: `execFile("ping", ["-c", "1", host]); // Sem shell`
  },
  // CWE-943: NoSQL Injection
  {
    category: "nosql-injection",
    name: "MongoDB Query Injection",
    cve: "CWE-943",
    vuln: `User.findOne({ username, password }); // password: { $gt: "" }`,
    fix: `User.findOne({ username }); await bcrypt.compare(password, user.hash);`
  },
  // CWE-611: XXE
  {
    category: "xxe",
    name: "XML External Entity",
    cve: "CWE-611",
    vuln: `xml2js.parseString(req.body); // Aceita entities externas`,
    fix: `new xml2js.Parser({ strict: true }); // Ou usar JSON`
  },
  // CWE-918: SSRF
  {
    category: "ssrf",
    name: "SSRF URL Fetch",
    cve: "CWE-918",
    vuln: `const response = await fetch(req.query.url);`,
    fix: `if (!ALLOWED_DOMAINS.includes(new URL(url).hostname)) throw new Error();`
  },
  // CWE-307: Missing Rate Limit
  {
    category: "rate-limit",
    name: "No Rate Limit Login",
    cve: "CWE-307",
    vuln: `app.post("/login", async (req, res) => { /* sem limite */ });`,
    fix: `app.post("/login", rateLimit({ windowMs: 15*60*1000, max: 5 }), ...);`
  },
  // CWE-434: Unrestricted Upload
  {
    category: "file-upload",
    name: "Upload Any File Type",
    cve: "CWE-434",
    vuln: `const upload = multer({ dest: "uploads/" }); // Aceita .exe, .php`,
    fix: `multer({ fileFilter: (req, file, cb) => { if (ALLOWED.includes(ext)) cb(null, true); } });`
  },
  // CWE-384: Session Fixation
  {
    category: "session",
    name: "Session Not Regenerated",
    cve: "CWE-384",
    vuln: `req.session.userId = user.id; // Não regenera session`,
    fix: `req.session.regenerate((err) => { req.session.userId = user.id; });`
  },
  // CWE-117: Log Injection
  {
    category: "log-injection",
    name: "Log Injection Newline",
    cve: "CWE-117",
    vuln: `console.log("Search: " + query); // query pode ter \\n`,
    fix: `console.log("Search:", query.replace(/[\\r\\n]/g, ""));`
  },
  // CWE-1021: Clickjacking
  {
    category: "clickjacking",
    name: "Missing X-Frame-Options",
    cve: "CWE-1021",
    vuln: `app.get("/", (req, res) => res.send(html)); // Sem headers`,
    fix: `app.use(helmet({ frameguard: { action: "deny" } }));`
  },
  // CWE-208: Timing Attack
  {
    category: "timing-attack",
    name: "String Compare Timing",
    cve: "CWE-208",
    vuln: `return input === secret; // Tempo revela informação`,
    fix: `return crypto.timingSafeEqual(Buffer.from(input), Buffer.from(secret));`
  },
  // CWE-330: Insecure Random
  {
    category: "insecure-random",
    name: "Math.random Token",
    cve: "CWE-330",
    vuln: `return Math.random().toString(36).substring(2);`,
    fix: `return crypto.randomBytes(32).toString("hex");`
  },
  // CWE-120: Buffer Overflow
  {
    category: "buffer",
    name: "Unchecked Buffer Size",
    cve: "CWE-120",
    vuln: `const buffer = Buffer.from(input); // Pode ser gigante`,
    fix: `if (input.length > MAX_SIZE) throw new Error("Too large");`
  },
  // CWE-601: Unvalidated Redirect
  {
    category: "unvalidated-redirect",
    name: "Logout Redirect Target",
    cve: "CWE-601",
    vuln: `res.redirect(req.query.next || "/");`,
    fix: `if (next.startsWith("/") && !next.startsWith("//")) res.redirect(next);`
  },
  // CWE-922: Sensitive LocalStorage
  {
    category: "storage",
    name: "Token in LocalStorage",
    cve: "CWE-922",
    vuln: `localStorage.setItem("token", authToken); // XSS pode roubar`,
    fix: `// Use httpOnly cookie instead`
  },
  // CWE-113: Header Injection
  {
    category: "header-injection",
    name: "Content-Disposition Injection",
    cve: "CWE-113",
    vuln: "res.setHeader(\"Content-Disposition\", `attachment; filename=\"${filename}\"`);",
    fix: `const safe = path.basename(filename).replace(/[^a-zA-Z0-9._-]/g, "");`
  },
  // CWE-362: Race Condition
  {
    category: "race-condition",
    name: "Balance Race Condition",
    cve: "CWE-362",
    vuln: `if (user.balance >= amount) { user.balance -= amount; await user.save(); }`,
    fix: `await prisma.$transaction(async (tx) => { /* atomic update */ });`
  },
  // Weak Password Policy
  {
    category: "password",
    name: "Weak Password Policy",
    cve: "CWE-521",
    vuln: `return password.length >= 4;`,
    fix: `return PasswordSchema.min(12).regex(/[A-Z]/).regex(/[0-9]/).safeParse(password).success;`
  },
  // Missing Input Length
  {
    category: "validation",
    name: "No Input Length Limit",
    cve: "CWE-20",
    vuln: `return input.toUpperCase(); // Input pode ser enorme`,
    fix: `if (input.length > 1000) throw new Error("Too long");`
  },
  // Sensitive Data in Logs
  {
    category: "logging",
    name: "Password in Log",
    cve: "CWE-532",
    vuln: `console.log("Login:", { email, password });`,
    fix: `console.log("Login:", { email, password: "[REDACTED]" });`
  },
  // Missing Security Headers
  {
    category: "headers",
    name: "Missing Security Headers",
    cve: "CWE-693",
    vuln: `// No helmet, no CSP, no HSTS`,
    fix: `app.use(helmet()); // Adiciona X-Frame-Options, CSP, HSTS, etc`
  },
  // Sensitive Data in Cache
  {
    category: "cache",
    name: "Password in Cache",
    cve: "CWE-524",
    vuln: `cache.set(userId, userData); // Inclui password hash`,
    fix: `cache.set(userId, { id: user.id, name: user.name }); // Só dados públicos`
  },
  // Eval User Input
  {
    category: "eval",
    name: "Eval User Input",
    cve: "CWE-95",
    vuln: `return eval(formula);`,
    fix: `if (!/^[0-9+\\-*/().\\s]+$/.test(formula)) throw new Error("Invalid");`
  },
  // Insecure TLS
  {
    category: "tls",
    name: "TLS 1.0 Enabled",
    cve: "CWE-326",
    vuln: `https.createServer({ minVersion: "TLSv1" });`,
    fix: `https.createServer({ minVersion: "TLSv1.2" });`
  },
  // Debug Mode in Production
  {
    category: "debug",
    name: "Debug Enabled Production",
    cve: "CWE-489",
    vuln: `app.get("/debug/env", (req, res) => res.json(process.env));`,
    fix: `if (process.env.NODE_ENV === "development") { /* debug routes */ }`
  },
  // Insufficient Entropy
  {
    category: "entropy",
    name: "Short Reset Token",
    cve: "CWE-331",
    vuln: `const token = Math.random().toString(36).slice(2, 8); // 6 chars`,
    fix: `const token = crypto.randomBytes(32).toString("hex"); // 64 chars`
  },
  // Exposed GraphQL Introspection
  {
    category: "graphql",
    name: "GraphQL Introspection",
    cve: "CWE-200",
    vuln: `new ApolloServer({ introspection: true }); // Expõe schema`,
    fix: `new ApolloServer({ introspection: process.env.NODE_ENV !== "production" });`
  },
  // Insecure WebSocket
  {
    category: "websocket",
    name: "WS No Origin Check",
    cve: "CWE-346",
    vuln: `wss.on("connection", (ws) => { /* aceita qualquer origem */ });`,
    fix: `if (!ALLOWED_ORIGINS.includes(req.headers.origin)) ws.close();`
  }
];

// ============================================================================
// GERADOR
// ============================================================================

function generateCase(template: typeof TEMPLATES[0], index: number): void {
  const date = new Date().toISOString().split("T")[0];
  const baseName = `${template.category}-${template.name.toLowerCase().replace(/\s+/g, "-").replace(/[^a-z0-9-]/g, "")}`;
  const dir = `./src/generated/${date}`;

  fs.mkdirSync(dir, { recursive: true });

  // Arquivo vulnerável
  fs.writeFileSync(
    `${dir}/${baseName}-vulnerable.ts`,
    `/**
 * ⚠️ CASE ${index}: ${template.name.toUpperCase()} - VULNERÁVEL
 * CVE: ${template.cve}
 * Gerado em ${date}
 */

// 🔴 CÓDIGO VULNERÁVEL:
${template.vuln}

// Explicação: Este código é vulnerável a ${template.name}
`
  );

  // Arquivo seguro
  fs.writeFileSync(
    `${dir}/${baseName}-secure.ts`,
    `/**
 * ✅ CASE ${index}: ${template.name.toUpperCase()} - SEGURO
 * CVE: ${template.cve}
 * Gerado em ${date}
 */

// ✅ CÓDIGO SEGURO:
${template.fix}

// Correção: Proteção contra ${template.name}
`
  );

  console.log(`✅ Generated: ${baseName} (${template.cve})`);
}

function generateDailyCases(count: number = 10): string[] {
  const generated: string[] = [];
  const shuffled = [...TEMPLATES].sort(() => Math.random() - 0.5);

  for (let i = 0; i < Math.min(count, shuffled.length); i++) {
    generateCase(shuffled[i], i + 1);
    generated.push(shuffled[i].name);
  }

  return generated;
}

// ============================================================================
// CLI
// ============================================================================

if (process.argv[1]?.includes("generate-cases")) {
  console.log("🔄 Generating daily security cases...");
  console.log(`📚 Total templates: ${TEMPLATES.length}\n`);

  const cases = generateDailyCases(10);

  console.log(`\n✅ Generated ${cases.length} cases:`);
  cases.forEach((c, i) => console.log(`   ${i + 1}. ${c}`));
}

export { generateDailyCases, TEMPLATES };
