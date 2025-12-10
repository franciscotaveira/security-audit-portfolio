/**
 * ✅ CASE 9: SESSION FIXATION - SEGURO
 * Gerado automaticamente em 2025-12-10
 */

// ✅ SEGURO: Regenera session ID após login
export function login(session: any, userId: string): void {
  session.regenerate((err: Error) => {
    if (err) throw err;
    session.userId = userId;
    session.isAuthenticated = true;
  });
}