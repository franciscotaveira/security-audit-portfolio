/**
 * ✅ CASE 8: MISSING INPUT LENGTH LIMIT - SEGURO
 * Gerado automaticamente em 2025-12-10
 */

// ✅ SEGURO: Limite de tamanho
const MAX_INPUT_LENGTH = 1000;

export function processInput(input: string): string {
  if (input.length > MAX_INPUT_LENGTH) {
    throw new Error(`Input exceeds max length of ${MAX_INPUT_LENGTH}`);
  }
  return input.toUpperCase();
}