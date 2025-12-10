/**
 * ⚠️ CASE 3: TIMING ATTACK ON COMPARISON - VULNERÁVEL
 * Gerado automaticamente em 2025-12-10
 */

// 🔴 VULN: Comparação que vaza informação por timing
export function verifyToken(input: string, secret: string): boolean {
  return input === secret;
}