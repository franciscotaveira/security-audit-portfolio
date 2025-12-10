/**
 * ✅ CASE 8: SSRF (Server-Side Request Forgery) - SEGURO
 */

import { z } from "zod";
import dns from "dns";
import { promisify } from "util";

const dnsLookup = promisify(dns.lookup);

// ============================================================================
// VALIDAÇÃO DE URL
// ============================================================================

// Whitelist de domínios permitidos
const ALLOWED_DOMAINS = [
    "api.example.com",
    "webhook.trusted.com",
    "cdn.myapp.com",
];

// IPs bloqueados (internos)
const BLOCKED_IP_RANGES = [
    /^127\./, // localhost
    /^10\./, // Private Class A
    /^172\.(1[6-9]|2[0-9]|3[01])\./, // Private Class B
    /^192\.168\./, // Private Class C
    /^169\.254\./, // Link-local (AWS metadata!)
    /^0\./, // Invalid
    /^::1$/, // IPv6 localhost
    /^fc00:/, // IPv6 private
    /^fe80:/, // IPv6 link-local
];

/**
 * Valida se URL é segura para fazer request
 */
async function validateUrl(url: string): Promise<URL> {
    // Parse URL
    const parsed = new URL(url);

    // Só HTTPS em produção
    if (parsed.protocol !== "https:" && process.env.NODE_ENV === "production") {
        throw new Error("Only HTTPS URLs allowed in production");
    }

    // Verifica domínio na whitelist
    if (!ALLOWED_DOMAINS.includes(parsed.hostname)) {
        throw new Error(`Domain not in whitelist: ${parsed.hostname}`);
    }

    // Resolve DNS e verifica se IP não é interno
    try {
        const { address } = await dnsLookup(parsed.hostname);

        for (const range of BLOCKED_IP_RANGES) {
            if (range.test(address)) {
                throw new Error("Access to internal IPs is not allowed");
            }
        }
    } catch (err) {
        if ((err as Error).message.includes("internal")) throw err;
        throw new Error(`DNS resolution failed for: ${parsed.hostname}`);
    }

    return parsed;
}

// ============================================================================
// SERVICES SEGUROS
// ============================================================================

export class WebhookService {
    private readonly MAX_RESPONSE_SIZE = 1024 * 1024; // 1MB
    private readonly TIMEOUT_MS = 5000;

    /**
     * ✅ SEGURO: Valida URL antes de fazer request
     */
    async sendWebhook(url: string, data: unknown): Promise<void> {
        const validUrl = await validateUrl(url);

        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), this.TIMEOUT_MS);

        try {
            const response = await fetch(validUrl.href, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(data),
                signal: controller.signal,
                redirect: "error", // Não segue redirects
            });

            // Log sem expor resposta completa
            console.log(`[WEBHOOK] Sent to ${validUrl.hostname}: ${response.status}`);
        } finally {
            clearTimeout(timeout);
        }
    }

    /**
     * ✅ SEGURO: Proxy com whitelist restrita
     */
    async proxyRequest(targetUrl: string): Promise<string> {
        const validUrl = await validateUrl(targetUrl);

        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), this.TIMEOUT_MS);

        try {
            const response = await fetch(validUrl.href, {
                signal: controller.signal,
                redirect: "error",
            });

            // Limita tamanho da resposta
            const text = await response.text();
            if (text.length > this.MAX_RESPONSE_SIZE) {
                throw new Error("Response too large");
            }

            return text;
        } finally {
            clearTimeout(timeout);
        }
    }

    /**
     * ✅ SEGURO: Image fetcher com validação de content-type
     */
    async fetchImage(imageUrl: string): Promise<Buffer> {
        const validUrl = await validateUrl(imageUrl);

        const response = await fetch(validUrl.href, {
            redirect: "error",
        });

        // Verifica content-type
        const contentType = response.headers.get("content-type") || "";
        const ALLOWED_TYPES = ["image/jpeg", "image/png", "image/gif", "image/webp"];

        if (!ALLOWED_TYPES.some(t => contentType.includes(t))) {
            throw new Error(`Invalid content type: ${contentType}`);
        }

        // Verifica tamanho
        const contentLength = parseInt(response.headers.get("content-length") || "0");
        const MAX_IMAGE_SIZE = 5 * 1024 * 1024; // 5MB

        if (contentLength > MAX_IMAGE_SIZE) {
            throw new Error("Image too large");
        }

        return Buffer.from(await response.arrayBuffer());
    }
}

export class PdfService {
    // Whitelist de URLs permitidas para PDF
    private readonly ALLOWED_PDF_SOURCES = [
        /^https:\/\/myapp\.com\/public\//,
        /^https:\/\/docs\.myapp\.com\//,
    ];

    /**
     * ✅ SEGURO: Apenas URLs da whitelist podem gerar PDF
     */
    async generatePdfFromUrl(url: string): Promise<Buffer> {
        const isAllowed = this.ALLOWED_PDF_SOURCES.some(pattern => pattern.test(url));

        if (!isAllowed) {
            throw new Error("URL not allowed for PDF generation");
        }

        console.log(`[PDF] Generating from allowed URL: ${url}`);
        return Buffer.from("");
    }
}
