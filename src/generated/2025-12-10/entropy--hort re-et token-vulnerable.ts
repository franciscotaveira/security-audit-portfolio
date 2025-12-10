/**
 * ⚠️ CASE 6: SHORT RESET TOKEN - VULNERÁVEL
 * CVE: CWE-331
 * Gerado em 2025-12-10
 */

// 🔴 CÓDIGO VULNERÁVEL:
const token = Math.random().toString(36).slice(2, 8); // 6 chars

// Explicação: Este código é vulnerável a Short Reset Token
