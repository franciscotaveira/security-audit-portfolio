/**
 * ✅ CASE 3: SQL INJECTION - SEGURO
 * Usando prepared statements e validação
 */

import { z } from "zod";

// ============================================================================
// TIPOS
// ============================================================================

interface DbClient {
    query(sql: string, params: unknown[]): Promise<any[]>;
    execute(sql: string, params: unknown[]): Promise<void>;
}

const ProductSchema = z.object({
    id: z.number().int().positive(),
    name: z.string().min(1).max(200),
    category: z.string().min(1).max(100),
    price: z.number().positive(),
});

type Product = z.infer<typeof ProductSchema>;

// Whitelist de colunas permitidas para ORDER BY
const ALLOWED_ORDER_COLUMNS = ["id", "name", "price", "created_at"] as const;
type OrderColumn = (typeof ALLOWED_ORDER_COLUMNS)[number];

// ============================================================================
// REPOSITORY SEGURO
// ============================================================================

export class ProductRepository {
    constructor(private db: DbClient) { }

    /**
     * ✅ SEGURO: Usando parameterized query
     */
    async findByName(name: string): Promise<Product[]> {
        // Validação de input
        const validName = z.string().min(1).max(200).parse(name);

        // Prepared statement - parâmetro nunca é interpretado como SQL
        const sql = "SELECT * FROM products WHERE name = $1";
        const results = await this.db.query(sql, [validName]);

        return results.map((r) => ProductSchema.parse(r));
    }

    /**
     * ✅ SEGURO: Array de IDs com validação e placeholders
     */
    async findByIds(ids: number[]): Promise<Product[]> {
        // Validação: apenas números inteiros positivos
        const validIds = z.array(z.number().int().positive()).parse(ids);

        if (validIds.length === 0) return [];

        // Gera placeholders: $1, $2, $3...
        const placeholders = validIds.map((_, i) => `$${i + 1}`).join(", ");
        const sql = `SELECT * FROM products WHERE id IN (${placeholders})`;

        const results = await this.db.query(sql, validIds);
        return results.map((r) => ProductSchema.parse(r));
    }

    /**
     * ✅ SEGURO: ORDER BY com whitelist
     */
    async findAll(orderBy: string, direction: "ASC" | "DESC" = "ASC"): Promise<Product[]> {
        // Whitelist validation - só permite colunas conhecidas
        if (!ALLOWED_ORDER_COLUMNS.includes(orderBy as OrderColumn)) {
            throw new Error(`Invalid order column: ${orderBy}`);
        }

        // Direction também é validado pelo tipo
        const sql = `SELECT * FROM products ORDER BY ${orderBy} ${direction}`;
        const results = await this.db.query(sql, []);

        return results.map((r) => ProductSchema.parse(r));
    }

    /**
     * ✅ SEGURO: DELETE com parameterized query
     */
    async deleteByCategory(category: string): Promise<void> {
        const validCategory = z.string().min(1).max(100).parse(category);

        const sql = "DELETE FROM products WHERE category = $1";
        await this.db.execute(sql, [validCategory]);
    }

    /**
     * ✅ SEGURO: NoSQL filter com schema validation
     */
    async findByFilter(filter: unknown): Promise<Product[]> {
        // Schema rígido para o filtro
        const FilterSchema = z.object({
            category: z.string().optional(),
            minPrice: z.number().positive().optional(),
            maxPrice: z.number().positive().optional(),
        }).strict(); // Rejeita campos extras

        const validFilter = FilterSchema.parse(filter);

        // Constrói query segura
        const conditions: string[] = [];
        const params: unknown[] = [];
        let paramIndex = 1;

        if (validFilter.category) {
            conditions.push(`category = $${paramIndex++}`);
            params.push(validFilter.category);
        }
        if (validFilter.minPrice) {
            conditions.push(`price >= $${paramIndex++}`);
            params.push(validFilter.minPrice);
        }
        if (validFilter.maxPrice) {
            conditions.push(`price <= $${paramIndex++}`);
            params.push(validFilter.maxPrice);
        }

        const whereClause = conditions.length > 0
            ? `WHERE ${conditions.join(" AND ")}`
            : "";

        const sql = `SELECT * FROM products ${whereClause}`;
        const results = await this.db.query(sql, params);

        return results.map((r) => ProductSchema.parse(r));
    }
}
