/**
 * ⚠️ CASE 8: SSRF (Server-Side Request Forgery) - VULNERÁVEL
 */

export class WebhookService {
    // 🔴 VULN: Aceita qualquer URL sem validação
    async sendWebhook(url: string, data: any): Promise<void> {
        // Atacante pode usar: http://169.254.169.254/latest/meta-data/ (AWS metadata)
        // Ou: http://localhost:3000/admin/delete-all
        const response = await fetch(url, {
            method: "POST",
            body: JSON.stringify(data),
        });
        console.log("Webhook response:", await response.text());
    }

    // 🔴 VULN: Proxy que faz request para qualquer URL
    async proxyRequest(targetUrl: string): Promise<string> {
        const response = await fetch(targetUrl);
        return response.text();
    }

    // 🔴 VULN: Image fetcher sem validação
    async fetchImage(imageUrl: string): Promise<Buffer> {
        const response = await fetch(imageUrl);
        return Buffer.from(await response.arrayBuffer());
    }

    // 🔴 VULN: Redirect follow sem limite
    async fetchWithRedirects(url: string): Promise<string> {
        const response = await fetch(url, { redirect: "follow" });
        // Pode seguir redirects para URLs internas
        return response.text();
    }
}

export class PdfService {
    // 🔴 VULN: Gera PDF a partir de URL do usuário
    async generatePdfFromUrl(url: string): Promise<Buffer> {
        // Bibliotecas como puppeteer/wkhtmltopdf podem acessar URLs internas
        console.log("Generating PDF from:", url);
        return Buffer.from("");
    }
}
