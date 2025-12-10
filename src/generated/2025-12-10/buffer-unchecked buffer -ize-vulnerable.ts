/**
 * ⚠️ CASE 10: UNCHECKED BUFFER SIZE - VULNERÁVEL
 * CVE: CWE-120
 * Gerado em 2025-12-10
 */

// 🔴 CÓDIGO VULNERÁVEL:
const buffer = Buffer.from(input); // Pode ser gigante

// Explicação: Este código é vulnerável a Unchecked Buffer Size
