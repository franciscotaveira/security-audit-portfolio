/**
 * ✅ CASE 6: SENSITIVE DATA IN LOGS - SEGURO
 * Gerado automaticamente em 2025-12-10
 */

// ✅ SEGURO: Sanitiza antes de logar
const SENSITIVE_FIELDS = ["password", "token", "apiKey", "creditCard"];

export function logRequest(req: any): void {
  const sanitized = { ...req };
  for (const field of SENSITIVE_FIELDS) {
    if (sanitized[field]) sanitized[field] = "[REDACTED]";
  }
  console.log("Request:", JSON.stringify(sanitized));
}