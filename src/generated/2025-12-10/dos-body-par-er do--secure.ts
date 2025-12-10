/**
 * ✅ CASE 3: BODY-PARSER DOS - SEGURO
 * CVE: CVE-2024-45590
 * Gerado em 2025-12-10
 */

// ✅ CÓDIGO SEGURO:
app.use(bodyParser.urlencoded({ extended: true, limit: "1kb", parameterLimit: 10 }));

// Correção: Proteção contra Body-parser DoS
