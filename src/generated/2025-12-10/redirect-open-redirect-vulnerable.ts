/**
 * ⚠️ CASE 2: OPEN REDIRECT - VULNERÁVEL
 * Gerado automaticamente em 2025-12-10
 */

// 🔴 VULN: Redirect para qualquer URL
export function redirect(res: any, url: string): void {
  res.redirect(url);
}