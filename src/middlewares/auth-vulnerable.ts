/**
 * ⚠️ ORIGINAL CODE - VULNERÁVEL
 * Este arquivo contém o código original com todas as vulnerabilidades identificadas.
 * NÃO USE EM PRODUÇÃO - apenas para fins educacionais.
 */

import jwt from "jsonwebtoken";

export function auth(req: any, res: any, next: any) {
    const token = req.headers.authorization?.split(" ")[1];

    if (!token) {
        return res.status(401).send("missing token");
    }

    let data: any;
    try {
        data = jwt.verify(token, process.env.SECRET || "123");
    } catch (e) {
        console.log("token error", e); // 🔴 VULN: Expõe stack trace no console
        res.status(403).send("invalid token");
        return;
    }

    // gambiarra para preencher req.user
    req.user = data.user || data || {}; // 🔴 VULN: Aceita qualquer estrutura

    if (req.user && req.user.role === 'admin') {
        req.isAdmin = true; // 🔴 VULN: Privilege escalation fácil
    }

    next();
}
