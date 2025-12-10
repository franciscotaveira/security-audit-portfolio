/**
 * Repositório de usuários em memória
 * Implementação de IUserRepository para testes
 */

import type { User, IUserRepository } from "./user-service-secure";

export class InMemoryUserRepository implements IUserRepository {
    private users: Map<string, User> = new Map();

    async findById(id: string): Promise<User | null> {
        return this.users.get(id) ?? null;
    }

    async findByEmail(email: string): Promise<User | null> {
        for (const user of this.users.values()) {
            if (user.email === email) return user;
        }
        return null;
    }

    async save(user: User): Promise<User> {
        this.users.set(user.id, user);
        return user;
    }

    async findAll(): Promise<User[]> {
        return Array.from(this.users.values());
    }

    // Helper para testes
    clear(): void {
        this.users.clear();
    }
}

/**
 * Mock do serviço de email para testes
 */
export class MockEmailService {
    public sentEmails: Array<{ email: string; name: string }> = [];

    async sendWelcomeEmail(email: string, name: string): Promise<boolean> {
        this.sentEmails.push({ email, name });
        return true;
    }
}
