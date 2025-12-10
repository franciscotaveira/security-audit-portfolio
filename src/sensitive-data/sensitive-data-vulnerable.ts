/**
 * ⚠️ CASE 7: SENSITIVE DATA EXPOSURE - VULNERÁVEL
 */

import crypto from "crypto";

export class PasswordService {
    // 🔴 VULN: MD5 é inseguro para senhas
    hashPassword(password: string): string {
        return crypto.createHash("md5").update(password).digest("hex");
    }

    // 🔴 VULN: Sem salt - senhas iguais têm hash igual
    hashWithSha1(password: string): string {
        return crypto.createHash("sha1").update(password).digest("hex");
    }
}

export class UserRepository {
    // 🔴 VULN: Retorna senha no response
    async getUser(id: string): Promise<any> {
        const user = await this.db.findUser(id);
        return user; // Inclui passwordHash, apiKey, etc!
    }

    // 🔴 VULN: Log com dados sensíveis
    async login(email: string, password: string): Promise<any> {
        console.log(`Login attempt: email=${email}, password=${password}`);
        // ...
        return null;
    }

    // 🔴 VULN: Erro expõe se email existe
    async resetPassword(email: string): Promise<void> {
        const user = await this.db.findByEmail(email);
        if (!user) {
            throw new Error(`User not found: ${email}`);
        }
        // ...
    }

    private db: any;
}

export class ApiClient {
    // 🔴 VULN: API key em URL (fica no log do servidor)
    async callApi(endpoint: string, apiKey: string): Promise<any> {
        const url = `https://api.example.com/${endpoint}?key=${apiKey}`;
        console.log("Calling:", url);
        // ...
        return null;
    }

    // 🔴 VULN: Dados sensíveis em query string
    async trackUser(userId: string, cardNumber: string): Promise<void> {
        const url = `https://tracking.example.com?user=${userId}&card=${cardNumber}`;
        // URL fica em logs, histórico do browser, etc
    }
}
