/**
 * ✅ CASE 5: SENSITIVE DATA IN CACHE - SEGURO
 * Gerado automaticamente em 2025-12-10
 */

// ✅ SEGURO: Cache apenas dados públicos
const cache = new Map<string, any>();
const CACHE_FIELDS = ["id", "name", "avatar"];

export function getUserData(userId: string): any {
  if (cache.has(userId)) return cache.get(userId);
  const data = fetchFromDb(userId);
  const safeData = Object.fromEntries(
    Object.entries(data).filter(([k]) => CACHE_FIELDS.includes(k))
  );
  cache.set(userId, safeData);
  return safeData;
}