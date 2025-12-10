/**
 * ✅ CASE 9: DoS (Denial of Service) - SEGURO
 */

import { z } from "zod";

// ============================================================================
// RATE LIMITER
// ============================================================================

interface RateLimitStore {
    attempts: number;
    resetAt: number;
}

class RateLimiter {
    private store = new Map<string, RateLimitStore>();

    constructor(
        private maxAttempts: number,
        private windowMs: number
    ) { }

    isAllowed(key: string): boolean {
        const now = Date.now();
        const record = this.store.get(key);

        if (!record || now > record.resetAt) {
            this.store.set(key, { attempts: 1, resetAt: now + this.windowMs });
            return true;
        }

        if (record.attempts >= this.maxAttempts) {
            return false;
        }

        record.attempts++;
        return true;
    }

    getRemainingAttempts(key: string): number {
        const record = this.store.get(key);
        if (!record) return this.maxAttempts;
        return Math.max(0, this.maxAttempts - record.attempts);
    }
}

// ============================================================================
// CONTROLLER SEGURO
// ============================================================================

export class ApiController {
    // Rate limiters para diferentes operações
    private loginLimiter = new RateLimiter(5, 15 * 60 * 1000); // 5 tentativas / 15 min
    private uploadLimiter = new RateLimiter(10, 60 * 1000); // 10 uploads / minuto
    private apiLimiter = new RateLimiter(100, 60 * 1000); // 100 requests / minuto

    private readonly MAX_PAYLOAD_SIZE = 10 * 1024 * 1024; // 10MB
    private readonly MAX_ITEMS = 100;
    private readonly MAX_RECURSION_DEPTH = 10;
    private readonly MAX_JSON_SIZE = 1 * 1024 * 1024; // 1MB

    /**
     * ✅ SEGURO: Rate limiting no login
     */
    async login(email: string, password: string, clientIp: string): Promise<boolean> {
        const key = `login:${clientIp}:${email}`;

        if (!this.loginLimiter.isAllowed(key)) {
            const remaining = this.loginLimiter.getRemainingAttempts(key);
            throw new RateLimitError("Too many login attempts", remaining);
        }

        return this.checkCredentials(email, password);
    }

    /**
     * ✅ SEGURO: Limite de tamanho de upload
     */
    async uploadFile(body: Buffer, clientIp: string): Promise<void> {
        // Rate limit
        if (!this.uploadLimiter.isAllowed(`upload:${clientIp}`)) {
            throw new RateLimitError("Upload rate limit exceeded", 0);
        }

        // Limite de tamanho
        if (body.length > this.MAX_PAYLOAD_SIZE) {
            throw new PayloadTooLargeError(this.MAX_PAYLOAD_SIZE);
        }

        console.log(`[UPLOAD] Received file: ${body.length} bytes`);
    }

    /**
     * ✅ SEGURO: Regex safe (sem backtracking)
     */
    validateEmail(email: string): boolean {
        // Regex simples e linear - sem grupos repetidos aninhados
        const safeEmailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

        // Limite de tamanho antes do regex
        if (email.length > 254) return false;

        return safeEmailRegex.test(email);
    }

    /**
     * ✅ SEGURO: Limite de items processados
     */
    async processItems(items: unknown[]): Promise<void> {
        // Valida e limita array
        const ItemsSchema = z.array(z.unknown()).max(this.MAX_ITEMS);
        const validItems = ItemsSchema.parse(items);

        for (const item of validItems) {
            await this.processItem(item);
        }
    }

    /**
     * ✅ SEGURO: Paginação obrigatória
     */
    async getAllUsers(page = 1, limit = 20): Promise<{ users: unknown[]; total: number }> {
        // Limita valores
        const safePage = Math.max(1, Math.min(page, 1000));
        const safeLimit = Math.max(1, Math.min(limit, 100));

        const offset = (safePage - 1) * safeLimit;

        // Query paginada
        const users = await this.db.findUsers({ offset, limit: safeLimit });
        const total = await this.db.countUsers();

        return { users, total };
    }

    /**
     * ✅ SEGURO: Recursão com limite de profundidade
     */
    async processNestedData(data: unknown, depth = 0): Promise<void> {
        if (depth > this.MAX_RECURSION_DEPTH) {
            throw new Error(`Max recursion depth exceeded: ${this.MAX_RECURSION_DEPTH}`);
        }

        const DataSchema = z.object({
            value: z.unknown().optional(),
            children: z.array(z.unknown()).max(10).optional(),
        });

        const validated = DataSchema.parse(data);

        if (validated.children) {
            for (const child of validated.children) {
                await this.processNestedData(child, depth + 1);
            }
        }
    }

    /**
     * ✅ SEGURO: JSON parse com limite de tamanho
     */
    async parseJson(jsonString: string): Promise<unknown> {
        if (jsonString.length > this.MAX_JSON_SIZE) {
            throw new PayloadTooLargeError(this.MAX_JSON_SIZE);
        }

        return JSON.parse(jsonString);
    }

    private async checkCredentials(email: string, password: string): Promise<boolean> {
        return false;
    }

    private async processItem(item: unknown): Promise<void> { }

    private db = {
        findUsers: async (opts: { offset: number; limit: number }) => [],
        countUsers: async () => 0,
    };
}

// ============================================================================
// CUSTOM ERRORS
// ============================================================================

export class RateLimitError extends Error {
    constructor(message: string, public remaining: number) {
        super(message);
        this.name = "RateLimitError";
    }
}

export class PayloadTooLargeError extends Error {
    constructor(maxSize: number) {
        super(`Payload exceeds maximum size of ${maxSize} bytes`);
        this.name = "PayloadTooLargeError";
    }
}
