/**
 * ⚠️ ORIGINAL CODE - VULNERÁVEL
 * UserService com múltiplos anti-patterns e vulnerabilidades
 */

import fs from 'fs';

export class UserService {
    users: any[] = []; // 🔴 VULN: Tipagem any

    constructor() {
        // 🔴 VULN: Sync I/O bloqueia event loop
        // 🔴 VULN: Path hardcoded - path traversal possível
        // 🔴 VULN: Sem tratamento de erro
        const data = fs.readFileSync('./data/users.json', 'utf8');
        this.users = JSON.parse(data); // 🔴 VULN: JSON.parse sem try/catch
    }

    getUser(id: any) { // 🔴 VULN: id pode ser injetado
        return this.users.filter((u) => {
            if (u.id == id) return true; // 🔴 VULN: == ao invés de === (type coercion)
        })[0];
    }

    saveUser(u: any) { // 🔴 VULN: Aceita qualquer objeto
        this.users.push(u); // 🔴 VULN: Sem validação
        // 🔴 VULN: Sync write bloqueia
        // 🔴 VULN: Sem sanitização - prototype pollution possível
        fs.writeFileSync('./data/users.json', JSON.stringify(this.users));
        return true;
    }

    sendWelcomeEmail(email: string) {
        // 🔴 ANTI-PATTERN: Service misturando IO, DB e email (violação SRP)
        // 🔴 VULN: Email não validado
        console.log("Enviando email para ", email);
    }
}
