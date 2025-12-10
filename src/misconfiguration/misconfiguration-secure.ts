/**
 * ✅ CASE 6: SECURITY MISCONFIGURATION - SEGURO
 */

import express, { Request, Response, NextFunction } from "express";
import helmet from "helmet";
import cors from "cors";
import rateLimit from "express-rate-limit";

// ============================================================================
// APP SEGURO
// ============================================================================

export function createSecureApp() {
    const app = express();

    // ✅ SEGURO: Remove X-Powered-By
    app.disable("x-powered-by");

    // ✅ SEGURO: Helmet adiciona headers de segurança
    app.use(helmet({
        contentSecurityPolicy: {
            directives: {
                defaultSrc: ["'self'"],
                scriptSrc: ["'self'"],
                styleSrc: ["'self'", "'unsafe-inline'"],
                imgSrc: ["'self'", "data:", "https:"],
            },
        },
        hsts: {
            maxAge: 31536000,
            includeSubDomains: true,
        },
    }));

    // ✅ SEGURO: CORS restrito
    app.use(cors({
        origin: process.env.ALLOWED_ORIGINS?.split(",") || ["https://myapp.com"],
        methods: ["GET", "POST", "PUT", "DELETE"],
        allowedHeaders: ["Content-Type", "Authorization"],
        credentials: true,
        maxAge: 86400,
    }));

    // ✅ SEGURO: Rate limiting
    app.use(rateLimit({
        windowMs: 15 * 60 * 1000, // 15 minutos
        max: 100, // 100 requests por IP
        message: { error: "Too many requests, please try again later" },
        standardHeaders: true,
        legacyHeaders: false,
    }));

    // ✅ SEGURO: Error handler sem expor detalhes
    app.use((err: Error, req: Request, res: Response, _next: NextFunction) => {
        // Log interno detalhado
        console.error("[ERROR]", {
            message: err.message,
            path: req.path,
            method: req.method,
            timestamp: new Date().toISOString(),
            // Stack trace apenas no log, não na resposta
        });

        // Resposta genérica para o cliente
        const statusCode = (err as any).statusCode || 500;
        res.status(statusCode).json({
            error: statusCode === 500 ? "Internal server error" : err.message,
            code: (err as any).code || "UNKNOWN_ERROR",
        });
    });

    // ✅ SEGURO: Sem debug routes em produção
    if (process.env.NODE_ENV === "development") {
        app.get("/debug/health", (req, res) => {
            res.json({ status: "ok", env: "development" });
        });
    }

    // ✅ SEGURO: Static files com opções seguras
    app.use("/uploads", express.static("./uploads", {
        dotfiles: "deny",
        index: false, // Sem directory listing
        maxAge: "1h",
    }));

    return app;
}

// ============================================================================
// CONFIG SEGURO
// ============================================================================

/**
 * Configuração segura que lê de environment variables
 */
export function getSecureConfig() {
    const requiredEnvVars = [
        "DATABASE_URL",
        "JWT_SECRET",
        "ALLOWED_ORIGINS",
    ];

    // Fail fast se variáveis obrigatórias não existem
    for (const envVar of requiredEnvVars) {
        if (!process.env[envVar]) {
            throw new Error(`Missing required environment variable: ${envVar}`);
        }
    }

    return {
        database: {
            url: process.env.DATABASE_URL!, // Do env, nunca hardcoded
            ssl: process.env.NODE_ENV === "production",
            poolSize: parseInt(process.env.DB_POOL_SIZE || "10"),
        },

        auth: {
            jwtSecret: process.env.JWT_SECRET!,
            jwtExpiresIn: process.env.JWT_EXPIRES_IN || "1h",
        },

        server: {
            port: parseInt(process.env.PORT || "3000"),
            env: process.env.NODE_ENV || "development",
        },

        security: {
            rateLimit: true,
            cors: {
                origins: process.env.ALLOWED_ORIGINS!.split(","),
            },
        },
    };
}
