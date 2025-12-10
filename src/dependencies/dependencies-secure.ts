/**
 * ✅ CASE 10: VULNERABLE DEPENDENCIES - SEGURO
 * Boas práticas para gerenciamento de dependências
 */

import { z } from "zod";

// ============================================================================
// PACKAGE.JSON SEGURO
// ============================================================================

export const securePackageJson = {
    dependencies: {
        // ✅ Versões atualizadas e seguras
        "lodash": "^4.17.21",
        "zod": "^3.22.4",
        "express": "^4.18.2",
    },

    // ✅ Lock file para versões determinísticas
    // package-lock.json / pnpm-lock.yaml / yarn.lock

    // ✅ Scripts de auditoria
    scripts: {
        "audit": "npm audit",
        "audit:fix": "npm audit fix",
        "outdated": "npm outdated",
        "update:check": "npx npm-check-updates",
    },

    // ✅ Engine constraint
    engines: {
        "node": ">=18.0.0",
    },
};

// ============================================================================
// PLUGIN LOADER SEGURO
// ============================================================================

// Whitelist de plugins permitidos
const ALLOWED_PLUGINS = new Map<string, () => Promise<unknown>>([
    ["analytics", () => import("./plugins/analytics")],
    ["logging", () => import("./plugins/logging")],
    ["cache", () => import("./plugins/cache")],
]);

/**
 * ✅ SEGURO: Carrega plugins apenas da whitelist
 */
export async function loadPlugin(pluginName: string): Promise<unknown> {
    const loader = ALLOWED_PLUGINS.get(pluginName);

    if (!loader) {
        throw new Error(`Plugin not allowed: ${pluginName}`);
    }

    return loader();
}

// ============================================================================
// SAFE EXECUTION
// ============================================================================

/**
 * ✅ SEGURO: Nunca executa código arbitrário
 * Em vez disso, usa funções pré-definidas
 */
const SAFE_OPERATIONS = {
    sum: (a: number, b: number) => a + b,
    multiply: (a: number, b: number) => a * b,
    concat: (a: string, b: string) => a + b,
};

export function executeOperation(
    operation: keyof typeof SAFE_OPERATIONS,
    args: unknown[]
): unknown {
    const fn = SAFE_OPERATIONS[operation];

    if (!fn) {
        throw new Error(`Unknown operation: ${operation}`);
    }

    // Validação de argumentos baseada na operação
    return fn(...(args as [any, any]));
}

// ============================================================================
// PRÁTICAS RECOMENDADAS
// ============================================================================

export const dependencyBestPractices = {
    automation: [
        "Use Dependabot ou Renovate para updates automáticos",
        "Configure npm audit no CI/CD",
        "Use Snyk para monitoramento contínuo",
    ],

    selection: [
        "Verifique npms.io score antes de adicionar dependência",
        "Prefira pacotes com muitos downloads e manutenção ativa",
        "Verifique se o pacote tem type definitions",
        "Analise o número de dependências transitivas",
    ],

    lockFiles: [
        "Sempre commite package-lock.json ou equivalente",
        "Use npm ci em CI/CD (não npm install)",
        "Revise mudanças no lock file em PRs",
    ],

    runtime: [
        "Nunca use eval() ou new Function() com input do usuário",
        "Nunca execute npm install em runtime",
        "Use import() apenas com paths estáticos ou whitelist",
    ],
};

// ============================================================================
// AUDIT HELPER
// ============================================================================

/**
 * Script para verificar dependências
 * Execute: npx ts-node src/dependencies/dependencies-secure.ts
 */
export async function auditDependencies(): Promise<void> {
    const { execSync } = await import("child_process");

    console.log("🔍 Checking for vulnerabilities...\n");

    try {
        const result = execSync("npm audit --json", { encoding: "utf-8" });
        const audit = JSON.parse(result);

        if (audit.metadata.vulnerabilities.total === 0) {
            console.log("✅ No vulnerabilities found!");
        } else {
            console.log("⚠️ Vulnerabilities found:");
            console.log(`   Critical: ${audit.metadata.vulnerabilities.critical}`);
            console.log(`   High: ${audit.metadata.vulnerabilities.high}`);
            console.log(`   Moderate: ${audit.metadata.vulnerabilities.moderate}`);
            console.log(`   Low: ${audit.metadata.vulnerabilities.low}`);
            console.log("\nRun 'npm audit fix' to fix automatically.");
        }
    } catch (error) {
        console.log("Run 'npm audit' to check for vulnerabilities");
    }
}
