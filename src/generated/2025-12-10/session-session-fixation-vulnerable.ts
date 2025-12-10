/**
 * ⚠️ CASE 9: SESSION FIXATION - VULNERÁVEL
 * Gerado automaticamente em 2025-12-10
 */

// 🔴 VULN: Não regenera session após login
export function login(session: any, userId: string): void {
  session.userId = userId;
  session.isAuthenticated = true;
}