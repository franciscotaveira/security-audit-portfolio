/**
 * ✅ CASE 3: TIMING ATTACK ON COMPARISON - SEGURO
 * Gerado automaticamente em 2025-12-10
 */

// ✅ SEGURO: Comparação constante no tempo
import crypto from "crypto";

export function verifyToken(input: string, secret: string): boolean {
  const a = Buffer.from(input);
  const b = Buffer.from(secret);
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}