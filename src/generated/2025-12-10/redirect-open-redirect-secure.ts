/**
 * ✅ CASE 2: OPEN REDIRECT - SEGURO
 * Gerado automaticamente em 2025-12-10
 */

// ✅ SEGURO: Valida URL de redirect
const ALLOWED_HOSTS = ["myapp.com", "www.myapp.com"];

export function redirect(res: any, url: string): void {
  try {
    const parsed = new URL(url);
    if (!ALLOWED_HOSTS.includes(parsed.hostname)) {
      throw new Error("Invalid redirect URL");
    }
    res.redirect(url);
  } catch {
    res.redirect("/");
  }
}