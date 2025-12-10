/**
 * ⚠️ CASE 1: LOGOUT REDIRECT TARGET - VULNERÁVEL
 * CVE: CWE-601
 * Gerado em 2025-12-10
 */

// 🔴 CÓDIGO VULNERÁVEL:
res.redirect(req.query.next || "/");

// Explicação: Este código é vulnerável a Logout Redirect Target
