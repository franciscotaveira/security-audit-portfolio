/**
 * ⚠️ CASE 9: DoS (Denial of Service) - VULNERÁVEL
 */

export class ApiController {
    // 🔴 VULN: Sem rate limiting - permite brute force
    async login(email: string, password: string): Promise<boolean> {
        // Atacante pode tentar milhões de combinações
        return this.checkCredentials(email, password);
    }

    // 🔴 VULN: Sem limite de tamanho de payload
    async uploadFile(body: Buffer): Promise<void> {
        // Atacante pode enviar arquivo de 10GB
        console.log("Received file of size:", body.length);
    }

    // 🔴 VULN: ReDoS - Regex catastrófico
    validateEmail(email: string): boolean {
        // Este regex tem backtracking exponencial
        const regex = /^([a-zA-Z0-9]+)+@([a-zA-Z0-9]+)+\.([a-zA-Z0-9]+)+$/;
        return regex.test(email);
    }

    // 🔴 VULN: Loop infinito possível
    async processItems(items: any[]): Promise<void> {
        // Sem limite de items - pode travar o servidor
        for (const item of items) {
            await this.processItem(item);
        }
    }

    // 🔴 VULN: Query sem paginação
    async getAllUsers(): Promise<any[]> {
        // Se tiver 1 milhão de usuários, retorna todos de uma vez
        return this.db.findAllUsers();
    }

    // 🔴 VULN: Recursão sem limite
    async processNestedData(data: any, depth = 0): Promise<void> {
        // Atacante pode enviar objeto muito aninhado
        if (data.children) {
            for (const child of data.children) {
                await this.processNestedData(child, depth + 1);
            }
        }
    }

    // 🔴 VULN: JSON.parse com objeto muito grande
    async parseJson(jsonString: string): Promise<any> {
        // Pode consumir toda a memória
        return JSON.parse(jsonString);
    }

    private async checkCredentials(email: string, password: string): Promise<boolean> {
        return false;
    }

    private async processItem(item: any): Promise<void> { }

    private db: any;
}
