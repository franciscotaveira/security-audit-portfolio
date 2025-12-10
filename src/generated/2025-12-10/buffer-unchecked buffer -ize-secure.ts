/**
 * ✅ CASE 10: UNCHECKED BUFFER SIZE - SEGURO
 * CVE: CWE-120
 * Gerado em 2025-12-10
 */

// ✅ CÓDIGO SEGURO:
if (input.length > MAX_SIZE) throw new Error("Too large");

// Correção: Proteção contra Unchecked Buffer Size
