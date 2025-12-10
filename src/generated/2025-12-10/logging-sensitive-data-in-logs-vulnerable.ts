/**
 * ⚠️ CASE 6: SENSITIVE DATA IN LOGS - VULNERÁVEL
 * Gerado automaticamente em 2025-12-10
 */

// 🔴 VULN: Loga dados sensíveis
export function logRequest(req: any): void {
  console.log("Request:", JSON.stringify(req));
}