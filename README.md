# 🔐 Security Audit Portfolio - OWASP Top 10

> **Portfólio completo** de auditoria de segurança cobrindo as 10 principais vulnerabilidades OWASP com código vulnerável, versão corrigida e testes de exploração.

[![Tests](https://img.shields.io/badge/Tests-40%20passing-brightgreen)](./tests)
[![OWASP](https://img.shields.io/badge/OWASP-Top%2010-red)](https://owasp.org/Top10/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.3-blue?logo=typescript)](https://www.typescriptlang.org/)

## 📊 Cobertura OWASP Top 10

| # | Vulnerabilidade | Arquivos | Testes |
|---|----------------|----------|--------|
| 1 | **Broken Authentication** | `middlewares/auth-*` | 6 ✅ |
| 2 | **Insecure Deserialization** | `services/user-service-*` | 9 ✅ |
| 3 | **SQL Injection** | `injection/sql-*` | 3 ✅ |
| 4 | **XSS (Cross-Site Scripting)** | `xss/xss-*` | 3 ✅ |
| 5 | **Broken Access Control** | `access-control/*` | 3 ✅ |
| 6 | **Security Misconfiguration** | `misconfiguration/*` | 3 ✅ |
| 7 | **Sensitive Data Exposure** | `sensitive-data/*` | 3 ✅ |
| 8 | **SSRF** | `ssrf/ssrf-*` | 3 ✅ |
| 9 | **DoS (Rate Limiting)** | `dos/dos-*` | 3 ✅ |
| 10 | **Vulnerable Dependencies** | `dependencies/*` | 3 ✅ |

**Total: 40 testes demonstrando exploits e correções**

## 🚀 Quick Start

```bash
git clone https://github.com/SEU_USUARIO/security-audit-portfolio.git
cd security-audit-portfolio
npm install
npm test
```

## 📁 Estrutura

```
src/
├── middlewares/          # Case 1: JWT Auth
├── services/             # Case 2: User Service
├── injection/            # Case 3: SQL Injection
├── xss/                  # Case 4: XSS
├── access-control/       # Case 5: Access Control
├── misconfiguration/     # Case 6: Config
├── sensitive-data/       # Case 7: Data Exposure
├── ssrf/                 # Case 8: SSRF
├── dos/                  # Case 9: Rate Limiting
└── dependencies/         # Case 10: Dependencies

tests/
├── auth-exploit.test.ts
├── user-service-exploit.test.ts
└── owasp-top10-exploit.test.ts

docs/
├── SECURITY_REPORT.md
├── PROPOSAL_TEMPLATE.md
└── OWASP_CHECKLIST.md
```

## ⚠️ Aviso Legal

> **Este repositório é apenas para demonstração de portfólio.**
> 
> O código está protegido por direitos autorais e **NÃO pode ser copiado, redistribuído ou utilizado** sem permissão expressa do autor.

## 💼 Licenciamento Comercial

Interessado em usar este código ou contratar uma auditoria de segurança?

📧 **Entre em contato:**
- GitHub: [@franciscotaveira](https://github.com/franciscotaveira)
- LinkedIn: [Francisco Taveira](https://linkedin.com/in/franciscotaveira)

### Serviços disponíveis:
- 🔐 **Auditoria de Segurança** - R$ 1.500 - R$ 8.000
- 📦 **Licença Comercial** - Use este template no seu projeto
- 🎓 **Consultoria/Treinamento** - Segurança para sua equipe

## 📄 Licença

**Proprietary License - All Rights Reserved**

© 2024 Francisco Taveira
