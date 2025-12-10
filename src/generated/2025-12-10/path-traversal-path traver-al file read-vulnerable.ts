/**
 * ⚠️ CASE 5: PATH TRAVERSAL FILE READ - VULNERÁVEL
 * CVE: CWE-22
 * Gerado em 2025-12-10
 */

// 🔴 CÓDIGO VULNERÁVEL:
fs.readFileSync("./uploads/" + filename);

// Explicação: Este código é vulnerável a Path Traversal File Read
