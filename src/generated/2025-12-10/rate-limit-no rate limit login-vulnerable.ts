/**
 * ⚠️ CASE 9: NO RATE LIMIT LOGIN - VULNERÁVEL
 * CVE: CWE-307
 * Gerado em 2025-12-10
 */

// 🔴 CÓDIGO VULNERÁVEL:
app.post("/login", async (req, res) => { /* sem limite */ });

// Explicação: Este código é vulnerável a No Rate Limit Login
