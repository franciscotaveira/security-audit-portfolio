/**
 * ⚠️ CASE 9: JWT NONE ALGORITHM - VULNERÁVEL
 * CVE: CWE-347
 * Gerado em 2025-12-10
 */

// 🔴 CÓDIGO VULNERÁVEL:
jwt.verify(token, secret); // Aceita alg: none

// Explicação: Este código é vulnerável a JWT None Algorithm
