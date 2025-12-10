/**
 * ✅ CASE 1: LOGOUT REDIRECT TARGET - SEGURO
 * CVE: CWE-601
 * Gerado em 2025-12-10
 */

// ✅ CÓDIGO SEGURO:
if (next.startsWith("/") && !next.startsWith("//")) res.redirect(next);

// Correção: Proteção contra Logout Redirect Target
