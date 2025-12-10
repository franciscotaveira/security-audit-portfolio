/**
 * ⚠️ CASE 7: EXPRESS RES.REDIRECT XSS - VULNERÁVEL
 * CVE: CVE-2024-43796
 * Gerado em 2025-12-10
 */

// 🔴 CÓDIGO VULNERÁVEL:
app.get("/redirect", (req, res) => { res.redirect(req.query.url); });

// Explicação: Este código é vulnerável a Express res.redirect XSS
