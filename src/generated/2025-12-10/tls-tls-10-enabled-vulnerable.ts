/**
 * ⚠️ CASE 3: TLS 1.0 ENABLED - VULNERÁVEL
 * CVE: CWE-326
 * Gerado em 2025-12-10
 */

// 🔴 CÓDIGO VULNERÁVEL:
https.createServer({ minVersion: "TLSv1" });

// Explicação: Este código é vulnerável a TLS 1.0 Enabled
