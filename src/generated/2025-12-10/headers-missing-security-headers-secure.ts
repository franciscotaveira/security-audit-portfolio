/**
 * ✅ CASE 7: MISSING SECURITY HEADERS - SEGURO
 * Gerado automaticamente em 2025-12-10
 */

// ✅ SEGURO: Headers de segurança
export function setupApp(app: any): void {
  app.use((req: any, res: any, next: any) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("X-XSS-Protection", "1; mode=block");
    res.setHeader("Strict-Transport-Security", "max-age=31536000");
    next();
  });
}