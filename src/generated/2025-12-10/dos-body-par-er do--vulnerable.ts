/**
 * ⚠️ CASE 3: BODY-PARSER DOS - VULNERÁVEL
 * CVE: CVE-2024-45590
 * Gerado em 2025-12-10
 */

// 🔴 CÓDIGO VULNERÁVEL:
app.use(bodyParser.urlencoded({ extended: true })); // Sem limite

// Explicação: Este código é vulnerável a Body-parser DoS
