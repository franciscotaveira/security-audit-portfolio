/**
 * ✅ CASE 4: JSON PARSE NO VALIDATION - SEGURO
 * CVE: CWE-502
 * Gerado em 2025-12-10
 */

// ✅ CÓDIGO SEGURO:
const data = UserSchema.parse(JSON.parse(jsonString)); // Valida com Zod

// Correção: Proteção contra JSON Parse No Validation
