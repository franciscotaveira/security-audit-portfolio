/**
 * ⚠️ CASE 2: TOKEN IN LOCALSTORAGE - VULNERÁVEL
 * CVE: CWE-922
 * Gerado em 2025-12-10
 */

// 🔴 CÓDIGO VULNERÁVEL:
localStorage.setItem("token", authToken); // XSS pode roubar

// Explicação: Este código é vulnerável a Token in LocalStorage
