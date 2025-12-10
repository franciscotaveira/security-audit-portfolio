/**
 * ⚠️ CASE 7: BALANCE RACE CONDITION - VULNERÁVEL
 * CVE: CWE-362
 * Gerado em 2025-12-10
 */

// 🔴 CÓDIGO VULNERÁVEL:
if (user.balance >= amount) { user.balance -= amount; await user.save(); }

// Explicação: Este código é vulnerável a Balance Race Condition
