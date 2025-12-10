# OWASP Security Checklist

Use this checklist for future security audits.

## Authentication (A07:2021)
- [ ] No hardcoded credentials
- [ ] Secure password hashing (bcrypt/argon2)
- [ ] Token expiration configured
- [ ] Refresh token rotation
- [ ] Rate limiting on auth endpoints

## Authorization (A01:2021)
- [ ] Role-based access control
- [ ] Resource ownership validation
- [ ] No privilege escalation paths
- [ ] Principle of least privilege

## Injection (A03:2021)
- [ ] Parameterized queries
- [ ] Input validation (Zod/Joi)
- [ ] Output encoding
- [ ] No eval() or dynamic code execution

## Cryptography (A02:2021)
- [ ] Strong algorithms only (HS256+)
- [ ] Secrets in environment variables
- [ ] No secrets in code/logs
- [ ] Proper key rotation strategy

## Security Misconfiguration (A05:2021)
- [ ] Production error handling
- [ ] Security headers configured
- [ ] CORS properly configured
- [ ] No unnecessary features enabled

## Logging & Monitoring (A09:2021)
- [ ] Sensitive data not logged
- [ ] Failed auth attempts logged
- [ ] Structured logging format
- [ ] Audit trail for critical actions

## Code Quality
- [ ] TypeScript strict mode
- [ ] No `any` types
- [ ] Async operations non-blocking
- [ ] SOLID principles followed
- [ ] Error handling comprehensive
