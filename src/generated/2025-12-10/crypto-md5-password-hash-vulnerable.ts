/**
 * ⚠️ CASE 1: MD5 PASSWORD HASH - VULNERÁVEL
 * CVE: CWE-328
 * Gerado em 2025-12-10
 */

// 🔴 CÓDIGO VULNERÁVEL:
crypto.createHash("md5").update(password).digest("hex");

// Explicação: Este código é vulnerável a MD5 Password Hash
