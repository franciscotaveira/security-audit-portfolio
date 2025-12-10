/**
 * ⚠️ CASE 5: SENSITIVE DATA IN CACHE - VULNERÁVEL
 * Gerado automaticamente em 2025-12-10
 */

// 🔴 VULN: Cache de dados sensíveis
const cache = new Map<string, any>();

export function getUserData(userId: string): any {
  if (cache.has(userId)) return cache.get(userId);
  const data = fetchFromDb(userId);
  cache.set(userId, data); // Inclui senha, tokens, etc
  return data;
}