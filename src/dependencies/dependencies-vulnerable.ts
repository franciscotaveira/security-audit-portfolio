/**
 * ⚠️ CASE 10: VULNERABLE DEPENDENCIES - VULNERÁVEL
 * Este arquivo demonstra problemas com dependências
 */

// 🔴 VULN: Versões antigas com CVEs conhecidas
export const vulnerablePackageJson = {
    dependencies: {
        // CVE-2021-23337: Prototype pollution
        "lodash": "4.17.19",

        // CVE-2022-24999: ReDoS vulnerability
        "qs": "6.5.2",

        // CVE-2021-3807: ReDoS in ansi-regex
        "ansi-regex": "5.0.0",

        // CVE-2022-0155: SSRF via follow-redirects
        "follow-redirects": "1.14.0",

        // CVE-2022-25883: ReDoS in semver
        "semver": "5.7.1",

        // CVE-2020-28469: Path traversal
        "glob-parent": "5.1.1",

        // CVE-2021-44906: Prototype pollution  
        "minimist": "1.2.5",

        // Pacote abandonado - sem patches de segurança
        "request": "2.88.2",
    }
};

// 🔴 VULN: Import dinâmico sem verificação
export async function loadPlugin(pluginName: string): Promise<any> {
    // Atacante pode carregar qualquer módulo
    return import(pluginName);
}

// 🔴 VULN: Executa código de pacote npm sem verificar
export async function installAndRun(packageName: string): Promise<void> {
    // npm install seguido de require é perigoso
    const { execSync } = await import("child_process");
    execSync(`npm install ${packageName}`);
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    require(packageName);
}

// 🔴 VULN: Usa eval para carregar código
export function executeRemoteCode(code: string): any {
    return eval(code);
}
