/**
 * ✅ CASE 6: SHORT RESET TOKEN - SEGURO
 * CVE: CWE-331
 * Gerado em 2025-12-10
 */

// ✅ CÓDIGO SEGURO:
const token = crypto.randomBytes(32).toString("hex"); // 64 chars

// Correção: Proteção contra Short Reset Token
