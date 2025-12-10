/**
 * ⚠️ CASE 4: XSS (Cross-Site Scripting) - VULNERÁVEL
 */

export class CommentService {
    // 🔴 VULN: Renderiza HTML sem sanitização
    renderComment(username: string, content: string): string {
        return `
      <div class="comment">
        <strong>${username}</strong>
        <p>${content}</p>
      </div>
    `;
    }

    // 🔴 VULN: innerHTML com dados do usuário
    renderUserProfile(userData: any): string {
        return `
      <div id="profile">
        <h1>${userData.name}</h1>
        <div>${userData.bio}</div>
        <a href="${userData.website}">Website</a>
      </div>
    `;
    }

    // 🔴 VULN: eval com input do usuário
    executeUserFormula(formula: string): number {
        return eval(formula); // NUNCA faça isso!
    }

    // 🔴 VULN: document.write (se fosse no browser)
    injectScript(scriptUrl: string): string {
        return `<script src="${scriptUrl}"></script>`;
    }

    // 🔴 VULN: Template literal sem escape em atributos
    createLink(url: string, text: string): string {
        return `<a href="${url}" onclick="track('${text}')">${text}</a>`;
    }
}
