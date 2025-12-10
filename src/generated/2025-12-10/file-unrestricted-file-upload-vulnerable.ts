/**
 * ⚠️ CASE 1: UNRESTRICTED FILE UPLOAD - VULNERÁVEL
 * Gerado automaticamente em 2025-12-10
 */

// 🔴 VULN: Aceita qualquer tipo de arquivo
export function uploadFile(filename: string, content: Buffer): void {
  fs.writeFileSync(`./uploads/${filename}`, content);
}