/**
 * ✅ CASE 7: SENSITIVE DATA EXPOSURE - SEGURO
 */

import crypto from "crypto";
import { z } from "zod";

// ============================================================================
// PASSWORD SERVICE SEGURO
// ============================================================================

export class PasswordService {
    private readonly SALT_ROUNDS = 12;
    private readonly PEPPER = process.env.PASSWORD_PEPPER || "";

    /**
     * ✅ SEGURO: Usa bcrypt-like approach com salt único
     * Em produção, usar bcrypt ou argon2
     */
    async hashPassword(password: string): Promise<string> {
        // Salt único por senha
        const salt = crypto.randomBytes(16).toString("hex");

        // PBKDF2 com muitas iterações (bcrypt é melhor, isso é demonstração)
        const hash = crypto.pbkdf2Sync(
            password + this.PEPPER,
            salt,
            100000, // Muitas iterações = mais lento = mais seguro
            64,
            "sha512"
        ).toString("hex");

        // Retorna salt + hash juntos
        return `${salt}:${hash}`;
    }

    /**
     * ✅ SEGURO: Verifica senha com timing-safe comparison
     */
    async verifyPassword(password: string, storedHash: string): Promise<boolean> {
        const [salt, hash] = storedHash.split(":");

        const testHash = crypto.pbkdf2Sync(
            password + this.PEPPER,
            salt,
            100000,
            64,
            "sha512"
        ).toString("hex");

        // Timing-safe comparison previne timing attacks
        return crypto.timingSafeEqual(
            Buffer.from(hash, "hex"),
            Buffer.from(testHash, "hex")
        );
    }
}

// ============================================================================
// USER REPOSITORY SEGURO
// ============================================================================

// Schema para sanitizar output
const SafeUserSchema = z.object({
    id: z.string(),
    email: z.string(),
    name: z.string(),
    role: z.string(),
    createdAt: z.string(),
}).strict(); // Remove campos extras

interface Database {
    findUser(id: string): Promise<Record<string, unknown> | null>;
    findByEmail(email: string): Promise<Record<string, unknown> | null>;
}

export class UserRepository {
    constructor(private db: Database) { }

    /**
     * ✅ SEGURO: Remove campos sensíveis antes de retornar
     */
    async getUser(id: string): Promise<z.infer<typeof SafeUserSchema> | null> {
        const user = await this.db.findUser(id);
        if (!user) return null;

        // Só retorna campos seguros
        return SafeUserSchema.parse(user);
    }

    /**
     * ✅ SEGURO: Log sem dados sensíveis
     */
    async login(email: string, _password: string): Promise<unknown> {
        // Mascara o email no log
        const maskedEmail = email.replace(/(.{2})(.*)(@.*)/, "$1***$3");
        console.log(`[AUTH] Login attempt: ${maskedEmail}`);

        // Nunca loga a senha!
        return null;
    }

    /**
     * ✅ SEGURO: Mesma resposta para email existente ou não
     */
    async resetPassword(email: string): Promise<void> {
        const user = await this.db.findByEmail(email);

        // Sempre retorna sucesso - não revela se email existe
        if (user) {
            // Envia email de reset (em background)
            console.log("[AUTH] Reset email queued");
        }

        // Log não revela se usuário existe
        console.log("[AUTH] Password reset processed");

        // Mesma resposta independente de o email existir
    }
}

// ============================================================================
// API CLIENT SEGURO
// ============================================================================

export class ApiClient {
    /**
     * ✅ SEGURO: API key no header, não na URL
     */
    async callApi(endpoint: string, apiKey: string): Promise<unknown> {
        // Log sem expor a key
        console.log(`[API] Calling: https://api.example.com/${endpoint}`);

        // Key vai no header Authorization
        const headers = {
            Authorization: `Bearer ${apiKey}`,
            "Content-Type": "application/json",
        };

        // fetch com headers seguros
        // const response = await fetch(url, { headers });
        return null;
    }

    /**
     * ✅ SEGURO: Dados sensíveis no body POST, não na URL
     */
    async trackUser(userId: string, cardNumber: string): Promise<void> {
        // Mascara número do cartão para log
        const maskedCard = cardNumber.slice(-4).padStart(cardNumber.length, "*");
        console.log(`[TRACK] Processing payment for user ${userId}, card: ${maskedCard}`);

        // Dados sensíveis vão no body, não na URL
        const body = JSON.stringify({
            userId,
            cardNumber, // Em produção, tokenizar o cartão
        });

        // POST com body criptografado sobre HTTPS
        // await fetch("https://tracking.example.com/secure", {
        //   method: "POST",
        //   headers: { "Content-Type": "application/json" },
        //   body,
        // });
    }
}
