/**
 * 🔄 AUTOMATED CASE GENERATOR
 * Gera novos cases de segurança automaticamente
 */

import fs from "fs";
import path from "path";

// ============================================================================
// BANCO DE VULNERABILIDADES
// ============================================================================

const VULNERABILITY_TEMPLATES = [
    {
        category: "authentication",
        name: "Weak Password Policy",
        vulnerable: `
// 🔴 VULN: Aceita senhas fracas
export function validatePassword(password: string): boolean {
  return password.length >= 4; // Muito curto!
}`,
        secure: `
// ✅ SEGURO: Política de senha forte
import { z } from "zod";

const PasswordSchema = z.string()
  .min(12, "Mínimo 12 caracteres")
  .regex(/[A-Z]/, "Precisa de maiúscula")
  .regex(/[a-z]/, "Precisa de minúscula")
  .regex(/[0-9]/, "Precisa de número")
  .regex(/[^A-Za-z0-9]/, "Precisa de caractere especial");

export function validatePassword(password: string): boolean {
  return PasswordSchema.safeParse(password).success;
}`,
        test: `
test("Senha fraca aceita pelo código vulnerável", () => {
  const weakPassword = "1234";
  console.log("🔴 VULN: Senha fraca aceita:", weakPassword);
  expect(weakPassword.length).toBe(4);
});`
    },
    {
        category: "validation",
        name: "Missing Input Length Limit",
        vulnerable: `
// 🔴 VULN: Sem limite de tamanho
export function processInput(input: string): string {
  return input.toUpperCase();
}`,
        secure: `
// ✅ SEGURO: Limite de tamanho
const MAX_INPUT_LENGTH = 1000;

export function processInput(input: string): string {
  if (input.length > MAX_INPUT_LENGTH) {
    throw new Error(\`Input exceeds max length of \${MAX_INPUT_LENGTH}\`);
  }
  return input.toUpperCase();
}`,
        test: `
test("Input gigante pode travar o sistema", () => {
  const hugeInput = "a".repeat(1000000);
  console.log("🔴 VULN: Input de", hugeInput.length, "chars aceito");
  expect(hugeInput.length).toBe(1000000);
});`
    },
    {
        category: "crypto",
        name: "Insecure Random",
        vulnerable: `
// 🔴 VULN: Math.random não é criptograficamente seguro
export function generateToken(): string {
  return Math.random().toString(36).substring(2);
}`,
        secure: `
// ✅ SEGURO: crypto.randomBytes para tokens
import crypto from "crypto";

export function generateToken(): string {
  return crypto.randomBytes(32).toString("hex");
}`,
        test: `
test("Math.random é previsível", () => {
  const token1 = Math.random().toString(36);
  console.log("🔴 VULN: Token gerado com Math.random:", token1);
  expect(token1.length).toBeLessThan(20);
});`
    },
    {
        category: "logging",
        name: "Sensitive Data in Logs",
        vulnerable: `
// 🔴 VULN: Loga dados sensíveis
export function logRequest(req: any): void {
  console.log("Request:", JSON.stringify(req));
}`,
        secure: `
// ✅ SEGURO: Sanitiza antes de logar
const SENSITIVE_FIELDS = ["password", "token", "apiKey", "creditCard"];

export function logRequest(req: any): void {
  const sanitized = { ...req };
  for (const field of SENSITIVE_FIELDS) {
    if (sanitized[field]) sanitized[field] = "[REDACTED]";
  }
  console.log("Request:", JSON.stringify(sanitized));
}`,
        test: `
test("Senha aparece no log", () => {
  const req = { email: "test@test.com", password: "secret123" };
  const log = JSON.stringify(req);
  console.log("🔴 VULN: Log contém senha:", log);
  expect(log).toContain("secret123");
});`
    },
    {
        category: "session",
        name: "Session Fixation",
        vulnerable: `
// 🔴 VULN: Não regenera session após login
export function login(session: any, userId: string): void {
  session.userId = userId;
  session.isAuthenticated = true;
}`,
        secure: `
// ✅ SEGURO: Regenera session ID após login
export function login(session: any, userId: string): void {
  session.regenerate((err: Error) => {
    if (err) throw err;
    session.userId = userId;
    session.isAuthenticated = true;
  });
}`,
        test: `
test("Session ID não muda após login", () => {
  const sessionId = "fixed-session-123";
  console.log("🔴 VULN: Session fixation possível:", sessionId);
  expect(sessionId).toBe("fixed-session-123");
});`
    },
    {
        category: "file",
        name: "Unrestricted File Upload",
        vulnerable: `
// 🔴 VULN: Aceita qualquer tipo de arquivo
export function uploadFile(filename: string, content: Buffer): void {
  fs.writeFileSync(\`./uploads/\${filename}\`, content);
}`,
        secure: `
// ✅ SEGURO: Valida extensão e content-type
const ALLOWED_EXTENSIONS = [".jpg", ".png", ".pdf"];
const MAX_FILE_SIZE = 5 * 1024 * 1024;

export function uploadFile(filename: string, content: Buffer): void {
  const ext = path.extname(filename).toLowerCase();
  if (!ALLOWED_EXTENSIONS.includes(ext)) {
    throw new Error("File type not allowed");
  }
  if (content.length > MAX_FILE_SIZE) {
    throw new Error("File too large");
  }
  const safeName = crypto.randomUUID() + ext;
  fs.writeFileSync(\`./uploads/\${safeName}\`, content);
}`,
        test: `
test("Arquivo .exe pode ser uploaded", () => {
  const maliciousFile = "malware.exe";
  console.log("🔴 VULN: Upload de arquivo perigoso:", maliciousFile);
  expect(maliciousFile).toContain(".exe");
});`
    },
    {
        category: "timing",
        name: "Timing Attack on Comparison",
        vulnerable: `
// 🔴 VULN: Comparação que vaza informação por timing
export function verifyToken(input: string, secret: string): boolean {
  return input === secret;
}`,
        secure: `
// ✅ SEGURO: Comparação constante no tempo
import crypto from "crypto";

export function verifyToken(input: string, secret: string): boolean {
  const a = Buffer.from(input);
  const b = Buffer.from(secret);
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}`,
        test: `
test("Comparação normal vaza timing", () => {
  const start = Date.now();
  "abc" === "abc";
  const time = Date.now() - start;
  console.log("🔴 VULN: Timing attack possível");
  expect(time).toBeLessThan(10);
});`
    },
    {
        category: "redirect",
        name: "Open Redirect",
        vulnerable: `
// 🔴 VULN: Redirect para qualquer URL
export function redirect(res: any, url: string): void {
  res.redirect(url);
}`,
        secure: `
// ✅ SEGURO: Valida URL de redirect
const ALLOWED_HOSTS = ["myapp.com", "www.myapp.com"];

export function redirect(res: any, url: string): void {
  try {
    const parsed = new URL(url);
    if (!ALLOWED_HOSTS.includes(parsed.hostname)) {
      throw new Error("Invalid redirect URL");
    }
    res.redirect(url);
  } catch {
    res.redirect("/");
  }
}`,
        test: `
test("Redirect para site malicioso", () => {
  const maliciousUrl = "https://evil.com/phishing";
  console.log("🔴 VULN: Open redirect para:", maliciousUrl);
  expect(maliciousUrl).toContain("evil.com");
});`
    },
    {
        category: "headers",
        name: "Missing Security Headers",
        vulnerable: `
// 🔴 VULN: Sem headers de segurança
export function setupApp(app: any): void {
  // Nenhum header configurado
}`,
        secure: `
// ✅ SEGURO: Headers de segurança
export function setupApp(app: any): void {
  app.use((req: any, res: any, next: any) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("X-XSS-Protection", "1; mode=block");
    res.setHeader("Strict-Transport-Security", "max-age=31536000");
    next();
  });
}`,
        test: `
test("Resposta sem X-Frame-Options", () => {
  const headers = {};
  console.log("🔴 VULN: Clickjacking possível sem X-Frame-Options");
  expect(headers).not.toHaveProperty("X-Frame-Options");
});`
    },
    {
        category: "cache",
        name: "Sensitive Data in Cache",
        vulnerable: `
// 🔴 VULN: Cache de dados sensíveis
const cache = new Map<string, any>();

export function getUserData(userId: string): any {
  if (cache.has(userId)) return cache.get(userId);
  const data = fetchFromDb(userId);
  cache.set(userId, data); // Inclui senha, tokens, etc
  return data;
}`,
        secure: `
// ✅ SEGURO: Cache apenas dados públicos
const cache = new Map<string, any>();
const CACHE_FIELDS = ["id", "name", "avatar"];

export function getUserData(userId: string): any {
  if (cache.has(userId)) return cache.get(userId);
  const data = fetchFromDb(userId);
  const safeData = Object.fromEntries(
    Object.entries(data).filter(([k]) => CACHE_FIELDS.includes(k))
  );
  cache.set(userId, safeData);
  return safeData;
}`,
        test: `
test("Cache contém dados sensíveis", () => {
  const cachedData = { id: "1", password: "hash", token: "abc" };
  console.log("🔴 VULN: Cache contém:", Object.keys(cachedData));
  expect(cachedData).toHaveProperty("password");
});`
    }
];

// ============================================================================
// GERADOR
// ============================================================================

function generateCase(template: typeof VULNERABILITY_TEMPLATES[0], index: number): void {
    const date = new Date().toISOString().split("T")[0];
    const baseName = `${template.category}-${template.name.toLowerCase().replace(/\s+/g, "-")}`;
    const dir = `./src/generated/${date}`;

    fs.mkdirSync(dir, { recursive: true });

    // Arquivo vulnerável
    fs.writeFileSync(
        `${dir}/${baseName}-vulnerable.ts`,
        `/**
 * ⚠️ CASE ${index}: ${template.name.toUpperCase()} - VULNERÁVEL
 * Gerado automaticamente em ${date}
 */
${template.vulnerable}`
    );

    // Arquivo seguro
    fs.writeFileSync(
        `${dir}/${baseName}-secure.ts`,
        `/**
 * ✅ CASE ${index}: ${template.name.toUpperCase()} - SEGURO
 * Gerado automaticamente em ${date}
 */
${template.secure}`
    );

    console.log(`✅ Generated: ${baseName}`);
}

function generateDailyCases(count: number = 10): string[] {
    const generated: string[] = [];
    const shuffled = [...VULNERABILITY_TEMPLATES].sort(() => Math.random() - 0.5);

    for (let i = 0; i < Math.min(count, shuffled.length); i++) {
        generateCase(shuffled[i], i + 1);
        generated.push(shuffled[i].name);
    }

    return generated;
}

// ============================================================================
// CLI
// ============================================================================

// ESM entry point
const isMainModule = import.meta.url.endsWith(process.argv[1]?.replace(/^file:\/\//, '') || '');

if (process.argv[1]?.includes('generate-cases')) {
    console.log("🔄 Generating daily security cases...\n");
    const cases = generateDailyCases(10);
    console.log(`\n✅ Generated ${cases.length} cases:`);
    cases.forEach((c, i) => console.log(`   ${i + 1}. ${c}`));
}

export { generateDailyCases, VULNERABILITY_TEMPLATES };
