/**
 * ⚠️ CASE 8: MISSING INPUT LENGTH LIMIT - VULNERÁVEL
 * Gerado automaticamente em 2025-12-10
 */

// 🔴 VULN: Sem limite de tamanho
export function processInput(input: string): string {
  return input.toUpperCase();
}