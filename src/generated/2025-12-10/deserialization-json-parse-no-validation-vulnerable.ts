/**
 * ⚠️ CASE 4: JSON PARSE NO VALIDATION - VULNERÁVEL
 * CVE: CWE-502
 * Gerado em 2025-12-10
 */

// 🔴 CÓDIGO VULNERÁVEL:
const data = JSON.parse(jsonString); // Aceita qualquer estrutura

// Explicação: Este código é vulnerável a JSON Parse No Validation
