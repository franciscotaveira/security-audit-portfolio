# 🔐 Solar Orion - Security Audit Portfolio

> **Complete OWASP Top 10 security audit portfolio** with vulnerable code, secure implementations, and interactive exploit demonstrations.

[![Tests](https://img.shields.io/badge/Tests-40%20passing-brightgreen)](./tests)
[![OWASP](https://img.shields.io/badge/OWASP-Top%2010-red)](https://owasp.org/Top10/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.3-blue?logo=typescript)](https://www.typescriptlang.org/)
[![React](https://img.shields.io/badge/React-18-61DAFB?logo=react)](https://react.dev/)

## 🌟 Live Demo

**[View Interactive Portfolio →](http://localhost:3000)**

## 📊 OWASP Top 10 Coverage

| # | Vulnerability | Files | Tests | Severity |
|---|--------------|-------|-------|----------|
| 1 | **Broken Access Control** | `access-control/*` | 3 ✅ | 🔴 Critical |
| 2 | **Cryptographic Failures** | `sensitive-data/*` | 3 ✅ | 🔴 Critical |
| 3 | **Injection** | `injection/*` | 3 ✅ | 🔴 Critical |
| 4 | **Insecure Design** | Services patterns | 9 ✅ | 🟠 High |
| 5 | **Security Misconfiguration** | `misconfiguration/*` | 3 ✅ | 🟠 High |
| 6 | **Vulnerable Dependencies** | `dependencies/*` | 3 ✅ | 🟡 Medium |
| 7 | **Auth & Session Failures** | `middlewares/*` | 6 ✅ | 🔴 Critical |
| 8 | **Data Integrity Failures** | `services/*` | 9 ✅ | 🟠 High |
| 9 | **Logging & Monitoring** | Best practices | 3 ✅ | 🟡 Medium |
| 10 | **SSRF** | `ssrf/*` | 3 ✅ | 🟠 High |

**Total: 40 tests demonstrating exploits and secure implementations**

## 🚀 Quick Start

### Backend Tests
```bash
# Clone the repository
git clone https://github.com/franciscotaveira/security-audit-portfolio.git
cd security-audit-portfolio

# Install dependencies
npm install

# Run all exploit tests
npm test

# Run with watch mode
npm run test:watch
```

### Interactive Web Portfolio
```bash
# Navigate to web folder
cd web

# Install dependencies
npm install

# Start development server
npm run dev

# Build for production
npm run build
```

## 📁 Project Structure

```
solar-orion/
├── src/
│   ├── middlewares/          # JWT Auth vulnerabilities
│   ├── services/             # User Service patterns
│   ├── injection/            # SQL/NoSQL Injection
│   ├── xss/                  # Cross-Site Scripting
│   ├── access-control/       # Authorization flaws
│   ├── misconfiguration/     # Security Misconfiguration
│   ├── sensitive-data/       # Data Exposure
│   ├── ssrf/                 # SSRF vulnerabilities
│   ├── dos/                  # DoS/Rate Limiting
│   ├── dependencies/         # Vulnerable Dependencies
│   └── generated/            # Auto-generated daily cases
│
├── web/                      # Interactive React Portfolio
│   ├── src/
│   │   ├── components/       # React components
│   │   ├── data/             # Vulnerability database
│   │   └── index.css         # Premium dark theme
│   └── dist/                 # Production build
│
├── tests/
│   ├── auth-exploit.test.ts
│   ├── user-service-exploit.test.ts
│   └── owasp-top10-exploit.test.ts
│
├── docs/
│   ├── SECURITY_REPORT.md
│   ├── PROPOSAL_TEMPLATE.md
│   └── OWASP_CHECKLIST.md
│
├── scripts/
│   └── generate-cases.ts     # Daily CVE case generator
│
└── .github/
    └── workflows/
        ├── ci.yml            # CI/CD pipeline
        └── codeql.yml        # Security scanning
```

## ✨ Features

### 🎮 Interactive Web Portfolio
- **Premium dark theme** with glassmorphism design
- **10 OWASP categories** with detailed explanations
- **Side-by-side code comparison** (vulnerable vs secure)
- **Exploit demonstrations** for each vulnerability
- **Code Analyzer** - paste code to scan for vulnerabilities
- **Fully responsive** design

### 🤖 AI Security Analyzer
- Pattern-based vulnerability detection
- 15+ vulnerability patterns including:
  - SQL/NoSQL Injection
  - XSS (innerHTML)
  - Command Injection (exec)
  - Weak Cryptography (MD5)
  - JWT vulnerabilities
  - CORS misconfiguration
  - Prototype pollution
  - And more...

### 🔄 Daily Case Generation
- **45+ CVE-based templates**
- Automatic generation of 10 new cases daily
- Based on real CVEs (2024 and earlier)
- Categories include:
  - CVE-2024-43796: XSS in Express
  - CVE-2023-44487: HTTP/2 Rapid Reset
  - CVE-2021-23337: Prototype Pollution
  - And 40+ more...

### 🔁 CI/CD Pipeline
- **Automated testing** on every push
- **CodeQL security scanning**
- **Daily case generation** via GitHub Actions
- **Auto-deploy** to GitHub Pages
- **npm audit** security checks

## 📈 Statistics

| Metric | Value |
|--------|-------|
| OWASP Categories | 10 |
| Passing Tests | 40 |
| CVE Templates | 45+ |
| Generated Cases | 60+ |
| Test Coverage | 100% |

## ⚠️ Disclaimer

> **This repository is for educational and portfolio demonstration purposes only.**
> 
> The vulnerable code examples are intentionally insecure to demonstrate security flaws.
> **DO NOT** use vulnerable code in production environments.

## 💼 Commercial Licensing

Interested in using this code or hiring for a security audit?

📧 **Contact:**
- GitHub: [@franciscotaveira](https://github.com/franciscotaveira)
- LinkedIn: [Francisco Taveira](https://linkedin.com/in/franciscotaveira)

### Services Available:
- 🔐 **Security Audit** - R$ 1.500 - R$ 8.000
- 📦 **Commercial License** - Use this template in your project
- 🎓 **Consulting/Training** - Security training for your team

## 📄 License

**Proprietary License - All Rights Reserved**

© 2024 Francisco Taveira

This code is protected by copyright and **CANNOT be copied, redistributed, or used** without express permission from the author.
