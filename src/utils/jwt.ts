/**
 * Utilitários JWT Seguros
 * Funções auxiliares para geração e manipulação de tokens
 */

import jwt from "jsonwebtoken";

// ============================================================================
// TIPOS
// ============================================================================

export interface TokenPayload {
    sub: string;      // User ID (UUID)
    email: string;
    role: "user" | "admin" | "moderator";
}

export interface TokenOptions {
    expiresIn?: string;  // Default: "1h"
}

// ============================================================================
// FUNÇÕES
// ============================================================================

/**
 * Gera um token JWT de acesso
 */
export function generateAccessToken(
    payload: TokenPayload,
    options: TokenOptions = {}
): string {
    const secret = process.env.JWT_SECRET;

    if (!secret) {
        throw new Error("JWT_SECRET not configured");
    }

    return jwt.sign(payload, secret, {
        algorithm: "HS256",
        expiresIn: options.expiresIn || "1h",
    });
}

/**
 * Gera um token JWT de refresh (validade maior)
 */
export function generateRefreshToken(
    payload: Pick<TokenPayload, "sub">
): string {
    const secret = process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET;

    if (!secret) {
        throw new Error("JWT secret not configured");
    }

    return jwt.sign(payload, secret, {
        algorithm: "HS256",
        expiresIn: "7d",
    });
}

/**
 * Decodifica um token SEM verificar a assinatura
 * ⚠️ Use apenas para inspecionar tokens - NUNCA confie no resultado!
 */
export function decodeTokenUnsafe(token: string): unknown {
    return jwt.decode(token);
}
