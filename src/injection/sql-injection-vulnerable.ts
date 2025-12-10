/**
 * ⚠️ CASE 3: SQL INJECTION - VULNERÁVEL
 * Query vulnerável que aceita input direto do usuário
 */

// Simulando um cliente de banco de dados
interface DbClient {
    query(sql: string): Promise<any[]>;
    execute(sql: string): Promise<void>;
}

export class ProductRepository {
    constructor(private db: DbClient) { }

    // 🔴 VULN: SQL Injection - input concatenado diretamente
    async findByName(name: string): Promise<any[]> {
        const sql = `SELECT * FROM products WHERE name = '${name}'`;
        return this.db.query(sql);
    }

    // 🔴 VULN: SQL Injection em WHERE IN
    async findByIds(ids: string[]): Promise<any[]> {
        const sql = `SELECT * FROM products WHERE id IN (${ids.join(",")})`;
        return this.db.query(sql);
    }

    // 🔴 VULN: SQL Injection em ORDER BY
    async findAll(orderBy: string): Promise<any[]> {
        const sql = `SELECT * FROM products ORDER BY ${orderBy}`;
        return this.db.query(sql);
    }

    // 🔴 VULN: SQL Injection em DELETE
    async deleteByCategory(category: string): Promise<void> {
        const sql = `DELETE FROM products WHERE category = '${category}'`;
        await this.db.execute(sql);
    }

    // 🔴 VULN: NoSQL Injection (MongoDB-style)
    async findByFilter(filter: any): Promise<any[]> {
        // Em MongoDB: db.collection.find(filter)
        // Se filter vier direto do usuário: { "$gt": "" } pode bypassar
        return this.db.query(JSON.stringify(filter));
    }
}
