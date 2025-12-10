/**
 * ✅ CASE 1: MD5 PASSWORD HASH - SEGURO
 * CVE: CWE-328
 * Gerado em 2025-12-10
 */

// ✅ CÓDIGO SEGURO:
await bcrypt.hash(password, 12);

// Correção: Proteção contra MD5 Password Hash
