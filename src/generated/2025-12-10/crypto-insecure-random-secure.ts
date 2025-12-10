/**
 * ✅ CASE 4: INSECURE RANDOM - SEGURO
 * Gerado automaticamente em 2025-12-10
 */

// ✅ SEGURO: crypto.randomBytes para tokens
import crypto from "crypto";

export function generateToken(): string {
  return crypto.randomBytes(32).toString("hex");
}