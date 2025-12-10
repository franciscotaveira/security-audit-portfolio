/**
 * ⚠️ CASE 5: HTTP2 RAPID RESET DOS - VULNERÁVEL
 * CVE: CVE-2023-44487
 * Gerado em 2025-12-10
 */

// 🔴 CÓDIGO VULNERÁVEL:
const server = http2.createSecureServer({}); // Sem limite de streams

// Explicação: Este código é vulnerável a HTTP2 Rapid Reset DoS
