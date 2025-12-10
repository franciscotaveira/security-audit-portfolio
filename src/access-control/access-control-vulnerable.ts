/**
 * ⚠️ CASE 5: BROKEN ACCESS CONTROL - VULNERÁVEL
 */

export class DocumentController {
    // 🔴 VULN: IDOR - Não verifica se o documento pertence ao usuário
    async getDocument(req: any, res: any): Promise<void> {
        const docId = req.params.id;
        const doc = await this.db.findDocument(docId);
        res.json(doc); // Qualquer usuário pode ver qualquer documento!
    }

    // 🔴 VULN: Horizontal privilege escalation
    async updateUserProfile(req: any, res: any): Promise<void> {
        const userId = req.body.userId; // Usuário pode alterar qualquer perfil!
        await this.db.updateUser(userId, req.body);
        res.json({ success: true });
    }

    // 🔴 VULN: Vertical privilege escalation
    async makeAdmin(req: any, res: any): Promise<void> {
        // Qualquer usuário autenticado pode se tornar admin!
        await this.db.updateUser(req.body.userId, { role: "admin" });
        res.json({ success: true });
    }

    // 🔴 VULN: Forced browsing
    async getAdminPanel(req: any, res: any): Promise<void> {
        // Não verifica se usuário é admin
        const stats = await this.db.getAdminStats();
        res.json(stats);
    }

    // 🔴 VULN: Path traversal
    async downloadFile(req: any, res: any): Promise<void> {
        const filename = req.params.filename;
        // Atacante pode usar: ../../../etc/passwd
        res.sendFile(`./uploads/${filename}`);
    }

    private db: any;
}
