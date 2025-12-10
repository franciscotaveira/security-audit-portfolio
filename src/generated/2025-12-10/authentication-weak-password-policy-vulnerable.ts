/**
 * ⚠️ CASE 10: WEAK PASSWORD POLICY - VULNERÁVEL
 * Gerado automaticamente em 2025-12-10
 */

// 🔴 VULN: Aceita senhas fracas
export function validatePassword(password: string): boolean {
  return password.length >= 4; // Muito curto!
}