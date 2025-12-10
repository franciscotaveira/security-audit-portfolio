/**
 * ✅ CASE 5: BROKEN ACCESS CONTROL - SEGURO
 */

import { z } from "zod";
import path from "path";

// ============================================================================
// TIPOS
// ============================================================================

interface AuthenticatedRequest {
    user: { id: string; role: "user" | "admin" };
    params: Record<string, string>;
    body: unknown;
}

interface Response {
    json(data: unknown): void;
    status(code: number): Response;
    sendFile(path: string): void;
}

interface Database {
    findDocument(id: string): Promise<{ id: string; ownerId: string; content: string } | null>;
    updateUser(id: string, data: unknown): Promise<void>;
    getAdminStats(): Promise<unknown>;
}

// ============================================================================
// CONTROLLER SEGURO
// ============================================================================

export class DocumentController {
    constructor(private db: Database) { }

    /**
     * ✅ SEGURO: Verifica ownership do documento
     */
    async getDocument(req: AuthenticatedRequest, res: Response): Promise<void> {
        const docId = z.string().uuid().parse(req.params.id);
        const doc = await this.db.findDocument(docId);

        if (!doc) {
            res.status(404).json({ error: "Document not found" });
            return;
        }

        // Verifica se o usuário é dono OU admin
        if (doc.ownerId !== req.user.id && req.user.role !== "admin") {
            res.status(403).json({ error: "Access denied" });
            return;
        }

        res.json(doc);
    }

    /**
     * ✅ SEGURO: Usuário só pode atualizar próprio perfil
     */
    async updateUserProfile(req: AuthenticatedRequest, res: Response): Promise<void> {
        // Ignora userId do body - usa o do token autenticado
        const userId = req.user.id;

        const UpdateSchema = z.object({
            name: z.string().max(100).optional(),
            email: z.string().email().optional(),
            bio: z.string().max(500).optional(),
        }).strict(); // Bloqueia campos extras como 'role'

        const data = UpdateSchema.parse(req.body);
        await this.db.updateUser(userId, data);

        res.json({ success: true });
    }

    /**
     * ✅ SEGURO: Apenas admins podem promover usuários
     */
    async makeAdmin(req: AuthenticatedRequest, res: Response): Promise<void> {
        // Verifica se quem está fazendo a ação é admin
        if (req.user.role !== "admin") {
            res.status(403).json({ error: "Admin access required" });
            return;
        }

        const targetUserId = z.string().uuid().parse(req.body);

        // Não permite remover próprios privilégios acidentalmente
        if (targetUserId === req.user.id) {
            res.status(400).json({ error: "Cannot modify own role" });
            return;
        }

        await this.db.updateUser(targetUserId, { role: "admin" });
        res.json({ success: true });
    }

    /**
     * ✅ SEGURO: Middleware de role antes de acessar admin panel
     */
    async getAdminPanel(req: AuthenticatedRequest, res: Response): Promise<void> {
        if (req.user.role !== "admin") {
            res.status(403).json({ error: "Admin access required" });
            return;
        }

        const stats = await this.db.getAdminStats();
        res.json(stats);
    }

    /**
     * ✅ SEGURO: Path traversal prevention
     */
    async downloadFile(req: AuthenticatedRequest, res: Response): Promise<void> {
        const filename = req.params.filename;

        // Sanitiza filename
        const safeName = path.basename(filename); // Remove ../ 

        // Valida extensão permitida
        const ALLOWED_EXTENSIONS = [".pdf", ".png", ".jpg", ".txt"];
        const ext = path.extname(safeName).toLowerCase();

        if (!ALLOWED_EXTENSIONS.includes(ext)) {
            res.status(400).json({ error: "File type not allowed" });
            return;
        }

        // Resolve path absoluto e verifica se está dentro do diretório permitido
        const uploadsDir = path.resolve("./uploads");
        const filePath = path.resolve(uploadsDir, safeName);

        if (!filePath.startsWith(uploadsDir)) {
            res.status(403).json({ error: "Access denied" });
            return;
        }

        res.sendFile(filePath);
    }
}
