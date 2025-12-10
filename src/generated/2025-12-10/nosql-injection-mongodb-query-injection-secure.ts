/**
 * ✅ CASE 6: MONGODB QUERY INJECTION - SEGURO
 * CVE: CWE-943
 * Gerado em 2025-12-10
 */

// ✅ CÓDIGO SEGURO:
User.findOne({ username }); await bcrypt.compare(password, user.hash);

// Correção: Proteção contra MongoDB Query Injection
