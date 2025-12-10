/**
 * ✅ CASE 10: WEAK PASSWORD POLICY - SEGURO
 * Gerado automaticamente em 2025-12-10
 */

// ✅ SEGURO: Política de senha forte
import { z } from "zod";

const PasswordSchema = z.string()
  .min(12, "Mínimo 12 caracteres")
  .regex(/[A-Z]/, "Precisa de maiúscula")
  .regex(/[a-z]/, "Precisa de minúscula")
  .regex(/[0-9]/, "Precisa de número")
  .regex(/[^A-Za-z0-9]/, "Precisa de caractere especial");

export function validatePassword(password: string): boolean {
  return PasswordSchema.safeParse(password).success;
}