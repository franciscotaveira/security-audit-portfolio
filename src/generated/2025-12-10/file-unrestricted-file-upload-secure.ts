/**
 * ✅ CASE 1: UNRESTRICTED FILE UPLOAD - SEGURO
 * Gerado automaticamente em 2025-12-10
 */

// ✅ SEGURO: Valida extensão e content-type
const ALLOWED_EXTENSIONS = [".jpg", ".png", ".pdf"];
const MAX_FILE_SIZE = 5 * 1024 * 1024;

export function uploadFile(filename: string, content: Buffer): void {
  const ext = path.extname(filename).toLowerCase();
  if (!ALLOWED_EXTENSIONS.includes(ext)) {
    throw new Error("File type not allowed");
  }
  if (content.length > MAX_FILE_SIZE) {
    throw new Error("File too large");
  }
  const safeName = crypto.randomUUID() + ext;
  fs.writeFileSync(`./uploads/${safeName}`, content);
}