/**
 * ✅ CASE 9: JWT NONE ALGORITHM - SEGURO
 * CVE: CWE-347
 * Gerado em 2025-12-10
 */

// ✅ CÓDIGO SEGURO:
jwt.verify(token, secret, { algorithms: ["HS256"] });

// Correção: Proteção contra JWT None Algorithm
