/**
 * ✅ AUTH MIDDLEWARE - VERSÃO SEGURA
 * Implementação corrigida com todas as boas práticas de segurança.
 */

import jwt from "jsonwebtoken";
import { Request, Response, NextFunction } from "express";
import { z } from "zod";

// ============================================================================
// TIPOS E SCHEMAS
// ============================================================================

/**
 * Schema Zod para validar a estrutura do payload JWT
 * Isso previne injeção de dados malformados
 */
const JwtPayloadSchema = z.object({
    sub: z.string().uuid(),           // ID do usuário (sempre UUID)
    email: z.string().email(),        // Email válido
    role: z.enum(["user", "admin", "moderator"]), // Roles permitidas
    iat: z.number(),                  // Issued at
    exp: z.number(),                  // Expiration
});

type JwtPayload = z.infer<typeof JwtPayloadSchema>;

/**
 * Extensão da interface Request do Express
 */
export interface AuthenticatedRequest extends Request {
    user: JwtPayload;
    isAdmin: boolean;
}

// ============================================================================
// CONFIGURAÇÃO
// ============================================================================

/**
 * Obtém o secret de forma segura
 * FALHA RÁPIDO se não configurado - nunca use fallback!
 */
function getJwtSecret(): string {
    const secret = process.env.JWT_SECRET;

    if (!secret) {
        throw new Error(
            "CRITICAL: JWT_SECRET environment variable is not set. " +
            "Application cannot start without proper secret configuration."
        );
    }

    if (secret.length < 32) {
        throw new Error(
            "CRITICAL: JWT_SECRET is too short. " +
            "Minimum 32 characters required for security."
        );
    }

    return secret;
}

// Valida na inicialização - fail fast
const JWT_SECRET = getJwtSecret();

// ============================================================================
// MIDDLEWARE PRINCIPAL
// ============================================================================

/**
 * Middleware de autenticação seguro
 * 
 * Funcionalidades:
 * - Validação estrutural do token
 * - Validação do payload via Zod
 * - Logging seguro (sem expor dados sensíveis)
 * - Tipagem forte
 */
export function authMiddleware(
    req: Request,
    res: Response,
    next: NextFunction
): void {
    const authHeader = req.headers.authorization;

    // Verifica formato do header
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        res.status(401).json({
            error: "unauthorized",
            message: "Missing or malformed authorization header",
            code: "AUTH_MISSING_TOKEN",
        });
        return;
    }

    const token = authHeader.substring(7); // Remove "Bearer "

    // Validação básica do formato do token (3 partes separadas por .)
    if (token.split(".").length !== 3) {
        res.status(401).json({
            error: "unauthorized",
            message: "Invalid token format",
            code: "AUTH_INVALID_FORMAT",
        });
        return;
    }

    try {
        // Verifica e decodifica o token
        const decoded = jwt.verify(token, JWT_SECRET, {
            algorithms: ["HS256"], // Força algoritmo específico (previne "none" attack)
            complete: false,
        });

        // Valida estrutura do payload
        const parseResult = JwtPayloadSchema.safeParse(decoded);

        if (!parseResult.success) {
            console.warn(
                `[AUTH] Invalid token payload structure from IP: ${req.ip}`,
                { errors: parseResult.error.flatten() }
            );

            res.status(403).json({
                error: "forbidden",
                message: "Token payload validation failed",
                code: "AUTH_INVALID_PAYLOAD",
            });
            return;
        }

        // Attach user data ao request
        const authReq = req as AuthenticatedRequest;
        authReq.user = parseResult.data;
        authReq.isAdmin = parseResult.data.role === "admin";

        // Log de acesso (sem dados sensíveis)
        console.log(
            `[AUTH] Access granted - User: ${authReq.user.sub.substring(0, 8)}... Role: ${authReq.user.role}`
        );

        next();
    } catch (error) {
        // Tratamento específico por tipo de erro
        if (error instanceof jwt.TokenExpiredError) {
            res.status(401).json({
                error: "unauthorized",
                message: "Token has expired",
                code: "AUTH_TOKEN_EXPIRED",
            });
            return;
        }

        if (error instanceof jwt.JsonWebTokenError) {
            // Log de tentativa suspeita (sem expor detalhes do erro)
            console.warn(`[AUTH] Invalid token attempt from IP: ${req.ip}`);

            res.status(403).json({
                error: "forbidden",
                message: "Invalid token",
                code: "AUTH_INVALID_TOKEN",
            });
            return;
        }

        // Erro inesperado - log interno mas resposta genérica
        console.error("[AUTH] Unexpected error during authentication", error);

        res.status(500).json({
            error: "internal_error",
            message: "Authentication service unavailable",
            code: "AUTH_INTERNAL_ERROR",
        });
    }
}

// ============================================================================
// MIDDLEWARES AUXILIARES
// ============================================================================

/**
 * Middleware para exigir role de admin
 * Deve ser usado APÓS authMiddleware
 */
export function requireAdmin(
    req: Request,
    res: Response,
    next: NextFunction
): void {
    const authReq = req as AuthenticatedRequest;

    if (!authReq.isAdmin) {
        console.warn(
            `[AUTH] Admin access denied for user: ${authReq.user?.sub?.substring(0, 8)}...`
        );

        res.status(403).json({
            error: "forbidden",
            message: "Admin access required",
            code: "AUTH_ADMIN_REQUIRED",
        });
        return;
    }

    next();
}

/**
 * Middleware para exigir roles específicas
 */
export function requireRole(...allowedRoles: JwtPayload["role"][]) {
    return (req: Request, res: Response, next: NextFunction): void => {
        const authReq = req as AuthenticatedRequest;

        if (!allowedRoles.includes(authReq.user?.role)) {
            res.status(403).json({
                error: "forbidden",
                message: `Required roles: ${allowedRoles.join(", ")}`,
                code: "AUTH_INSUFFICIENT_ROLE",
            });
            return;
        }

        next();
    };
}
