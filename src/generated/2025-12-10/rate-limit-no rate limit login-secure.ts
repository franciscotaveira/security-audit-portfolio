/**
 * ✅ CASE 9: NO RATE LIMIT LOGIN - SEGURO
 * CVE: CWE-307
 * Gerado em 2025-12-10
 */

// ✅ CÓDIGO SEGURO:
app.post("/login", rateLimit({ windowMs: 15*60*1000, max: 5 }), ...);

// Correção: Proteção contra No Rate Limit Login
