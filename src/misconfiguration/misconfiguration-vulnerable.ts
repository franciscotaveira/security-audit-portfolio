/**
 * ⚠️ CASE 6: SECURITY MISCONFIGURATION - VULNERÁVEL
 */

import express from "express";

export function createVulnerableApp() {
    const app = express();

    // 🔴 VULN: Expõe stack trace em produção
    app.use((err: any, req: any, res: any, next: any) => {
        console.log(err.stack);
        res.status(500).json({
            error: err.message,
            stack: err.stack, // NUNCA em produção!
            query: req.query,
            body: req.body,
        });
    });

    // 🔴 VULN: CORS aberto para todos
    app.use((req, res, next) => {
        res.header("Access-Control-Allow-Origin", "*");
        res.header("Access-Control-Allow-Headers", "*");
        res.header("Access-Control-Allow-Methods", "*");
        next();
    });

    // 🔴 VULN: Sem headers de segurança
    // Faltam: X-Frame-Options, X-Content-Type-Options, CSP, etc.

    // 🔴 VULN: Debug routes em produção
    app.get("/debug/env", (req, res) => {
        res.json(process.env); // Expõe todas as variáveis!
    });

    app.get("/debug/memory", (req, res) => {
        res.json(process.memoryUsage());
    });

    // 🔴 VULN: Directory listing habilitado
    app.use("/uploads", express.static("./uploads", { dotfiles: "allow" }));

    // 🔴 VULN: Versão do framework exposta
    // Express adiciona X-Powered-By: Express por padrão

    return app;
}

export const vulnerableConfig = {
    // 🔴 VULN: Senhas e secrets em config
    dbPassword: "admin123",
    jwtSecret: "super-secret-key",
    apiKey: "sk-1234567890",

    // 🔴 VULN: Debug habilitado em produção
    debug: true,
    verbose: true,

    // 🔴 VULN: SSL desabilitado
    ssl: false,

    // 🔴 VULN: Rate limit desabilitado
    rateLimit: false,
};
