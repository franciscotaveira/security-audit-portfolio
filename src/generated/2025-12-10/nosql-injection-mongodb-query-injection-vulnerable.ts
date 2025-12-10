/**
 * ⚠️ CASE 6: MONGODB QUERY INJECTION - VULNERÁVEL
 * CVE: CWE-943
 * Gerado em 2025-12-10
 */

// 🔴 CÓDIGO VULNERÁVEL:
User.findOne({ username, password }); // password: { $gt: "" }

// Explicação: Este código é vulnerável a MongoDB Query Injection
