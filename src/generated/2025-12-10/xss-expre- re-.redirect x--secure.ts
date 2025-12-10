/**
 * ✅ CASE 7: EXPRESS RES.REDIRECT XSS - SEGURO
 * CVE: CVE-2024-43796
 * Gerado em 2025-12-10
 */

// ✅ CÓDIGO SEGURO:
const url = new URL(req.query.url); if (!ALLOWED_HOSTS.includes(url.hostname)) return res.redirect("/");

// Correção: Proteção contra Express res.redirect XSS
