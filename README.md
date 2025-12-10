# 🔐 JWT Auth Security Audit

> **Case study**: Análise de segurança completa de um middleware de autenticação JWT vulnerável, com implementação corrigida e testes de exploração.

[![TypeScript](https://img.shields.io/badge/TypeScript-5.3-blue?logo=typescript)](https://www.typescriptlang.org/)
[![Vitest](https://img.shields.io/badge/Tested%20with-Vitest-6E9F18?logo=vitest)](https://vitest.dev/)
[![Security](https://img.shields.io/badge/Security-Audit-red)](./docs/SECURITY_REPORT.md)

## 📋 Sumário

- [Sobre o Projeto](#-sobre-o-projeto)
- [Vulnerabilidades Identificadas](#-vulnerabilidades-identificadas)
- [Quick Start](#-quick-start)
- [Estrutura do Projeto](#-estrutura-do-projeto)
- [Demonstração](#-demonstração)
- [Correções Implementadas](#-correções-implementadas)

## 🎯 Sobre o Projeto

Este repositório documenta uma **auditoria de segurança** realizada em um middleware de autenticação JWT comum em aplicações Node.js/Express. O código original apresentava múltiplas vulnerabilidades críticas que foram identificadas, documentadas e corrigidas.

### Objetivos

1. **Identificar** vulnerabilidades no código original
2. **Demonstrar** como cada vulnerabilidade pode ser explorada
3. **Implementar** versão segura seguindo melhores práticas
4. **Testar** que os exploits são bloqueados pela versão corrigida

## ⚠️ Vulnerabilidades Identificadas

| # | Vulnerabilidade | Severidade | CWE |
|---|----------------|------------|-----|
| 1 | Secret hardcoded como fallback | 🔴 Crítica | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) |
| 2 | Falta de tipagem (any) | 🟠 Alta | [CWE-20](https://cwe.mitre.org/data/definitions/20.html) |
| 3 | Validação insuficiente de payload | 🟠 Alta | [CWE-20](https://cwe.mitre.org/data/definitions/20.html) |
| 4 | Privilege escalation via token | 🔴 Crítica | [CWE-269](https://cwe.mitre.org/data/definitions/269.html) |
| 5 | Information leakage em logs | 🟡 Média | [CWE-532](https://cwe.mitre.org/data/definitions/532.html) |
| 6 | Falta de proteção contra algorithm confusion | 🟠 Alta | [CWE-327](https://cwe.mitre.org/data/definitions/327.html) |

## 🚀 Quick Start

```bash
# Clone o repositório
git clone https://github.com/SEU_USUARIO/jwt-auth-security-audit.git

# Instale as dependências
npm install

# Execute os testes de segurança
npm test
```

### Saída esperada:

```
✓ VULN: Fallback Secret Attack
  ✓ Atacante pode criar token válido com secret '123'
✓ VULN: Privilege Escalation  
  ✓ Usuário comum pode se elevar a admin
✓ VULN: Payload Structure Confusion
  ✓ Código aceita qualquer estrutura de payload
✓ SECURE: Proteções Implementadas
  ✓ Resumo das proteções na versão segura

Test Files  1 passed (1)
     Tests  6 passed (6)
```

## 📁 Estrutura do Projeto

```
├── src/
│   ├── middlewares/
│   │   ├── auth-vulnerable.ts    # ❌ Código original com vulnerabilidades
│   │   └── auth-secure.ts        # ✅ Implementação corrigida
│   └── utils/
│       └── jwt.ts                # Utilitários JWT seguros
├── tests/
│   └── auth-exploit.test.ts      # Testes de exploração
├── docs/
│   └── SECURITY_REPORT.md        # Relatório detalhado
└── README.md
```

## 🎬 Demonstração

### Código Vulnerável (Original)

```typescript
// ❌ Fallback perigoso - qualquer um pode forjar tokens
jwt.verify(token, process.env.SECRET || "123");

// ❌ Aceita qualquer estrutura
req.user = data.user || data || {};

// ❌ Privilege escalation trivial
if (req.user.role === 'admin') {
    req.isAdmin = true;
}
```

### Código Seguro (Corrigido)

```typescript
// ✅ Fail-fast se não configurado
function getJwtSecret(): string {
  const secret = process.env.JWT_SECRET;
  if (!secret) throw new Error("JWT_SECRET not configured");
  if (secret.length < 32) throw new Error("Secret too short");
  return secret;
}

// ✅ Validação com Zod
const JwtPayloadSchema = z.object({
  sub: z.string().uuid(),
  email: z.string().email(),
  role: z.enum(["user", "admin", "moderator"]),
});

// ✅ Força algoritmo específico
jwt.verify(token, JWT_SECRET, { algorithms: ["HS256"] });
```

## ✅ Correções Implementadas

| Vulnerabilidade | Correção |
|----------------|----------|
| Fallback secret | Fail-fast + mínimo 32 caracteres |
| Tipagem any | `AuthenticatedRequest` interface |
| Payload inseguro | Schema Zod com campos obrigatórios |
| Privilege escalation | Enum Zod + middleware `requireAdmin` |
| Information leakage | Logging estruturado sem stack traces |
| Algorithm confusion | `algorithms: ['HS256']` forçado |

## 📚 Referências

- [OWASP JWT Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [JWT Algorithm Confusion](https://portswigger.net/web-security/jwt/algorithm-confusion)
- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

## 📄 Licença

MIT License - Veja [LICENSE](./LICENSE) para detalhes.

---

<p align="center">
  <strong>🔒 Desenvolvido como case de segurança</strong><br>
  <sub>Análise e correções realizadas com auxílio do Antigravity AI</sub>
</p>
