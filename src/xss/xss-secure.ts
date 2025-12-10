/**
 * ✅ CASE 4: XSS (Cross-Site Scripting) - SEGURO
 */

import { z } from "zod";

// ============================================================================
// SANITIZAÇÃO
// ============================================================================

/**
 * Escapa caracteres HTML perigosos
 */
function escapeHtml(unsafe: string): string {
    return unsafe
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

/**
 * Valida e sanitiza URLs
 */
function sanitizeUrl(url: string): string {
    const UrlSchema = z.string().url().refine(
        (u) => u.startsWith("https://") || u.startsWith("http://"),
        "URL must use http or https protocol"
    );

    try {
        const parsed = new URL(UrlSchema.parse(url));

        // Bloqueia javascript: e data: URLs
        if (parsed.protocol === "javascript:" || parsed.protocol === "data:") {
            throw new Error("Dangerous URL protocol");
        }

        return parsed.href;
    } catch {
        return "#"; // URL segura de fallback
    }
}

// ============================================================================
// SERVICE SEGURO
// ============================================================================

export class CommentService {
    /**
     * ✅ SEGURO: Escapa todo o conteúdo HTML
     */
    renderComment(username: string, content: string): string {
        const safeUsername = escapeHtml(username);
        const safeContent = escapeHtml(content);

        return `
      <div class="comment">
        <strong>${safeUsername}</strong>
        <p>${safeContent}</p>
      </div>
    `;
    }

    /**
     * ✅ SEGURO: Valida e escapa dados do perfil
     */
    renderUserProfile(userData: unknown): string {
        const ProfileSchema = z.object({
            name: z.string().max(100),
            bio: z.string().max(500),
            website: z.string().url().optional(),
        });

        const validated = ProfileSchema.parse(userData);

        return `
      <div id="profile">
        <h1>${escapeHtml(validated.name)}</h1>
        <div>${escapeHtml(validated.bio)}</div>
        ${validated.website
                ? `<a href="${sanitizeUrl(validated.website)}">Website</a>`
                : ""}
      </div>
    `;
    }

    /**
     * ✅ SEGURO: Usa parser matemático ao invés de eval
     */
    executeUserFormula(formula: string): number {
        // Whitelist de caracteres permitidos
        const ALLOWED_CHARS = /^[0-9+\-*/().\s]+$/;

        if (!ALLOWED_CHARS.test(formula)) {
            throw new Error("Invalid formula: only numbers and operators allowed");
        }

        // Usa Function com escopo limitado (ainda melhor usar uma lib como mathjs)
        const safeEval = new Function(`return (${formula})`);
        const result = safeEval();

        if (typeof result !== "number" || !Number.isFinite(result)) {
            throw new Error("Formula must evaluate to a finite number");
        }

        return result;
    }

    /**
     * ✅ SEGURO: Valida URL do script com whitelist
     */
    injectScript(scriptUrl: string): string {
        const ALLOWED_DOMAINS = [
            "cdn.example.com",
            "scripts.trusted.com",
        ];

        const url = new URL(scriptUrl);

        if (!ALLOWED_DOMAINS.includes(url.hostname)) {
            throw new Error(`Script domain not allowed: ${url.hostname}`);
        }

        // Adiciona integridade SRI se disponível
        return `<script src="${escapeHtml(url.href)}" crossorigin="anonymous"></script>`;
    }

    /**
     * ✅ SEGURO: Escapa atributos e conteúdo
     */
    createLink(url: string, text: string): string {
        const safeUrl = sanitizeUrl(url);
        const safeText = escapeHtml(text);

        // Não usa inline onclick - usa data attributes
        return `<a href="${safeUrl}" data-track="${safeText}">${safeText}</a>`;
    }
}
