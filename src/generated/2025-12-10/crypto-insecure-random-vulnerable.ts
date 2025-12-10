/**
 * ⚠️ CASE 4: INSECURE RANDOM - VULNERÁVEL
 * Gerado automaticamente em 2025-12-10
 */

// 🔴 VULN: Math.random não é criptograficamente seguro
export function generateToken(): string {
  return Math.random().toString(36).substring(2);
}