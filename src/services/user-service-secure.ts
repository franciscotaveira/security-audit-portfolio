/**
 * ✅ USER SERVICE - VERSÃO SEGURA
 * Implementação seguindo SOLID, tipagem forte e boas práticas
 */

import { z } from "zod";

// ============================================================================
// TIPOS E SCHEMAS
// ============================================================================

export const UserSchema = z.object({
    id: z.string().uuid(),
    email: z.string().email(),
    name: z.string().min(2).max(100),
    role: z.enum(["user", "admin", "moderator"]),
    createdAt: z.string().datetime(),
    updatedAt: z.string().datetime(),
});

export type User = z.infer<typeof UserSchema>;

export const CreateUserSchema = UserSchema.omit({
    id: true,
    createdAt: true,
    updatedAt: true
});

export type CreateUserInput = z.infer<typeof CreateUserSchema>;

// ============================================================================
// INTERFACES (Dependency Inversion)
// ============================================================================

/**
 * Interface para repositório de usuários
 * Permite trocar implementação (memory, file, database) sem mudar service
 */
export interface IUserRepository {
    findById(id: string): Promise<User | null>;
    findByEmail(email: string): Promise<User | null>;
    save(user: User): Promise<User>;
    findAll(): Promise<User[]>;
}

/**
 * Interface para serviço de email
 * Separa responsabilidade de envio de email (SRP)
 */
export interface IEmailService {
    sendWelcomeEmail(email: string, name: string): Promise<boolean>;
}

// ============================================================================
// SERVICE (Seguindo SOLID)
// ============================================================================

export class UserService {
    constructor(
        private readonly userRepository: IUserRepository,
        private readonly emailService: IEmailService
    ) { }

    /**
     * Busca usuário por ID com validação
     */
    async getUser(id: string): Promise<User | null> {
        // Valida formato do ID antes de buscar
        const idValidation = z.string().uuid().safeParse(id);
        if (!idValidation.success) {
            throw new InvalidUserIdError(id);
        }

        return this.userRepository.findById(id);
    }

    /**
     * Cria usuário com validação completa
     */
    async createUser(input: CreateUserInput): Promise<User> {
        // Validação com Zod
        const validation = CreateUserSchema.safeParse(input);
        if (!validation.success) {
            throw new ValidationError(validation.error.flatten());
        }

        // Verifica email único
        const existing = await this.userRepository.findByEmail(input.email);
        if (existing) {
            throw new EmailAlreadyExistsError(input.email);
        }

        // Cria usuário com dados sanitizados
        const now = new Date().toISOString();
        const user: User = {
            id: crypto.randomUUID(),
            ...validation.data,
            createdAt: now,
            updatedAt: now,
        };

        // Salva e envia email de boas-vindas
        const saved = await this.userRepository.save(user);

        // Email em background (não bloqueia resposta)
        this.emailService.sendWelcomeEmail(saved.email, saved.name).catch((err) => {
            console.error("[UserService] Failed to send welcome email:", err.message);
        });

        return saved;
    }

    /**
     * Lista todos os usuários (paginado no futuro)
     */
    async listUsers(): Promise<User[]> {
        return this.userRepository.findAll();
    }
}

// ============================================================================
// CUSTOM ERRORS
// ============================================================================

export class InvalidUserIdError extends Error {
    constructor(id: string) {
        super(`Invalid user ID format: ${id.substring(0, 8)}...`);
        this.name = "InvalidUserIdError";
    }
}

export class EmailAlreadyExistsError extends Error {
    constructor(email: string) {
        // Não expõe email completo no erro
        const masked = email.replace(/(.{2})(.*)(@.*)/, "$1***$3");
        super(`Email already registered: ${masked}`);
        this.name = "EmailAlreadyExistsError";
    }
}

export class ValidationError extends Error {
    constructor(public readonly details: z.typeToFlattenedError<any>) {
        super("Validation failed");
        this.name = "ValidationError";
    }
}
