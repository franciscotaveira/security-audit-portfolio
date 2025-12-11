/**
 * ADVANCED SECURITY TESTS
 * Extended OWASP coverage with additional vulnerability patterns
 */

import { describe, it, expect } from 'vitest';

// ============================================================================
// CASE 11: API Security
// ============================================================================
describe('CASE 11: API Security', () => {

    it('Vulnerable: GraphQL introspection enabled', () => {
        // ❌ VULNERABLE: Introspection allowed in production
        const graphqlConfig = {
            introspection: true, // Exposes entire API schema
            playground: true,   // Debug tool in production
        };

        console.log('🔴 GRAPHQL INTROSPECTION ENABLED:');
        console.log('   Schema can be discovered by attackers');

        expect(graphqlConfig.introspection).toBe(true);
        expect(graphqlConfig.playground).toBe(true);
    });

    it('Secure: GraphQL introspection disabled in production', () => {
        // ✅ SECURE: Introspection disabled
        const isProd = process.env.NODE_ENV === 'production' || true;
        const graphqlConfig = {
            introspection: !isProd,
            playground: !isProd,
        };

        console.log('✅ GRAPHQL SECURED:');
        console.log('   Introspection:', graphqlConfig.introspection);
        console.log('   Playground:', graphqlConfig.playground);

        expect(graphqlConfig.introspection).toBe(false);
    });

    it('Vulnerable: Missing rate limiting on API', () => {
        // ❌ VULNERABLE: No rate limiting
        let requestCount = 0;
        const maxRequests = Infinity; // No limit!

        for (let i = 0; i < 1000; i++) {
            requestCount++;
        }

        console.log('🔴 NO RATE LIMITING:');
        console.log(`   Requests made: ${requestCount}`);
        console.log('   API can be abused!');

        expect(requestCount).toBe(1000);
        expect(maxRequests).toBe(Infinity);
    });
});

// ============================================================================
// CASE 12: Input Validation
// ============================================================================
describe('CASE 12: Input Validation', () => {

    it('Vulnerable: No input length validation', () => {
        // ❌ VULNERABLE: Accepts any length input
        const processInput = (input: string) => input;

        const hugePayload = 'x'.repeat(10_000_000); // 10MB string

        console.log('🔴 NO INPUT LENGTH LIMIT:');
        console.log(`   Payload size: ${hugePayload.length.toLocaleString()} chars`);
        console.log('   Can cause memory exhaustion!');

        expect(hugePayload.length).toBe(10_000_000);
    });

    it('Secure: Input length validation', () => {
        // ✅ SECURE: Validates input length
        const MAX_INPUT = 10_000;

        const processInput = (input: string): string | null => {
            if (input.length > MAX_INPUT) {
                return null; // Reject
            }
            return input;
        };

        const normalInput = 'Hello World';
        const hugeInput = 'x'.repeat(100_000);

        console.log('✅ INPUT LENGTH VALIDATED:');
        console.log(`   Max allowed: ${MAX_INPUT}`);
        console.log(`   Normal input accepted: ${processInput(normalInput) !== null}`);
        console.log(`   Huge input rejected: ${processInput(hugeInput) === null}`);

        expect(processInput(normalInput)).toBe(normalInput);
        expect(processInput(hugeInput)).toBeNull();
    });

    it('Vulnerable: Regex Denial of Service (ReDoS)', () => {
        // ❌ VULNERABLE: Catastrophic backtracking regex
        const evilRegex = /^([a-zA-Z0-9]+)+@/;
        const dangerousInput = 'a'.repeat(25) + '!';

        console.log('🔴 ReDoS VULNERABILITY:');
        console.log(`   Regex: ${evilRegex}`);
        console.log(`   Input: 'a' x 25 + '!'`);
        console.log('   Can freeze server for minutes!');

        // Don't actually run this - it would freeze!
        expect(evilRegex.toString()).toContain('+)+');
    });
});

// ============================================================================
// CASE 13: Session Security
// ============================================================================
describe('CASE 13: Session Security', () => {

    it('Vulnerable: Session fixation', () => {
        // ❌ VULNERABLE: Session not regenerated after login
        const session = {
            id: 'attacker-controlled-session-id',
            userId: null as string | null,
        };

        // User logs in but session ID stays the same
        session.userId = 'victim-user-123';

        console.log('🔴 SESSION FIXATION:');
        console.log(`   Session ID: ${session.id}`);
        console.log(`   User ID: ${session.userId}`);
        console.log('   Attacker knows session ID before login!');

        expect(session.id).toBe('attacker-controlled-session-id');
    });

    it('Secure: Session regeneration on login', () => {
        // ✅ SECURE: New session ID after login
        const generateSessionId = () =>
            Math.random().toString(36).substring(2) + Date.now().toString(36);

        let session = {
            id: 'old-session-id',
            userId: null as string | null,
        };

        // User logs in - regenerate session
        const oldSessionId = session.id;
        session = {
            id: generateSessionId(), // New ID!
            userId: 'victim-user-123',
        };

        console.log('✅ SESSION REGENERATED:');
        console.log(`   Old ID: ${oldSessionId}`);
        console.log(`   New ID: ${session.id}`);

        expect(session.id).not.toBe(oldSessionId);
    });

    it('Vulnerable: Cookies without security flags', () => {
        // ❌ VULNERABLE: Cookies without HttpOnly/Secure
        const insecureCookie = {
            name: 'session',
            value: 'abc123',
            httpOnly: false,  // Accessible via JavaScript
            secure: false,    // Sent over HTTP
            sameSite: 'none' as const, // No CSRF protection
        };

        console.log('🔴 INSECURE COOKIE:');
        console.log(`   HttpOnly: ${insecureCookie.httpOnly}`);
        console.log(`   Secure: ${insecureCookie.secure}`);
        console.log(`   SameSite: ${insecureCookie.sameSite}`);

        expect(insecureCookie.httpOnly).toBe(false);
        expect(insecureCookie.secure).toBe(false);
    });

    it('Secure: Cookies with proper security flags', () => {
        // ✅ SECURE: All security flags set
        const secureCookie = {
            name: 'session',
            value: 'abc123',
            httpOnly: true,   // Not accessible via JS
            secure: true,     // HTTPS only
            sameSite: 'strict' as const, // CSRF protection
            maxAge: 3600,     // 1 hour expiry
        };

        console.log('✅ SECURE COOKIE:');
        console.log(`   HttpOnly: ${secureCookie.httpOnly}`);
        console.log(`   Secure: ${secureCookie.secure}`);
        console.log(`   SameSite: ${secureCookie.sameSite}`);

        expect(secureCookie.httpOnly).toBe(true);
        expect(secureCookie.secure).toBe(true);
        expect(secureCookie.sameSite).toBe('strict');
    });
});

// ============================================================================
// CASE 14: Error Handling
// ============================================================================
describe('CASE 14: Error Handling', () => {

    it('Vulnerable: Detailed error messages exposed', () => {
        // ❌ VULNERABLE: Stack traces and internal info exposed
        const createErrorResponse = (error: Error) => ({
            error: error.message,
            stack: error.stack,
            query: 'SELECT * FROM users WHERE id = 1',
            internalPath: '/app/src/db.ts',
        });

        const testError = new Error('Database connection failed');
        const response = createErrorResponse(testError);

        console.log('🔴 DETAILED ERROR EXPOSED:');
        console.log('   Response:', JSON.stringify(response, null, 2));

        expect(response.stack).toBeDefined();
        expect(response.query).toBeDefined();
    });

    it('Secure: Generic error messages', () => {
        // ✅ SECURE: Generic user-facing errors
        const createErrorResponse = (error: Error, requestId: string) => {
            // Log internally with full details
            console.log(`[${requestId}] Internal Error:`, error.message);

            // Return generic response to user
            return {
                error: 'An error occurred',
                requestId, // For support reference
            };
        };

        const testError = new Error('Database connection failed at /app/db.ts:45');
        const response = createErrorResponse(testError, 'req-123');

        console.log('✅ GENERIC ERROR RESPONSE:');
        console.log('   Response:', JSON.stringify(response));

        expect(response.error).toBe('An error occurred');
        expect(response).not.toHaveProperty('stack');
        expect(response).not.toHaveProperty('query');
    });
});

// ============================================================================
// CASE 15: Timing Attacks
// ============================================================================
describe('CASE 15: Timing Attacks', () => {

    it('Vulnerable: Non-constant time comparison', () => {
        // ❌ VULNERABLE: Early return leaks timing info
        const insecureCompare = (a: string, b: string): boolean => {
            if (a.length !== b.length) return false;
            for (let i = 0; i < a.length; i++) {
                if (a[i] !== b[i]) return false; // Early return!
            }
            return true;
        };

        const secret = 'super-secret-token';

        console.log('🔴 TIMING ATTACK VULNERABLE:');
        console.log('   Early return on mismatch exposes timing info');
        console.log('   Attacker can guess secret character by character');

        expect(insecureCompare(secret, secret)).toBe(true);
        expect(insecureCompare(secret, 'wrong')).toBe(false);
    });

    it('Secure: Constant time comparison', () => {
        // ✅ SECURE: Always takes same time
        const constantTimeCompare = (a: string, b: string): boolean => {
            if (a.length !== b.length) {
                // Pad to prevent length timing
                b = b.padEnd(a.length, '\0');
            }

            let result = 0;
            for (let i = 0; i < a.length; i++) {
                result |= a.charCodeAt(i) ^ b.charCodeAt(i);
            }
            return result === 0;
        };

        const secret = 'super-secret-token';

        console.log('✅ CONSTANT TIME COMPARISON:');
        console.log('   XOR-based comparison prevents timing attacks');

        expect(constantTimeCompare(secret, secret)).toBe(true);
        expect(constantTimeCompare(secret, 'wrong-token-here!')).toBe(false);
    });
});

// ============================================================================
// CASE 16: File Upload Security
// ============================================================================
describe('CASE 16: File Upload Security', () => {

    it('Vulnerable: Unrestricted file upload', () => {
        // ❌ VULNERABLE: No file type validation
        const isFileAllowed = (_filename: string) => true; // Allows everything!

        const maliciousFiles = [
            'shell.php',
            'backdoor.exe',
            'payload.js',
            'evil.html',
        ];

        console.log('🔴 UNRESTRICTED FILE UPLOAD:');
        maliciousFiles.forEach(file => {
            console.log(`   ${file}: ${isFileAllowed(file) ? '✓ Allowed' : '✗ Blocked'}`);
        });

        expect(isFileAllowed('shell.php')).toBe(true);
    });

    it('Secure: Whitelisted file extensions', () => {
        // ✅ SECURE: Only allow safe extensions
        const ALLOWED_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.gif', '.pdf'];
        const MAX_SIZE = 5 * 1024 * 1024; // 5MB

        const isFileAllowed = (filename: string, size: number): boolean => {
            const ext = filename.slice(filename.lastIndexOf('.')).toLowerCase();
            return ALLOWED_EXTENSIONS.includes(ext) && size <= MAX_SIZE;
        };

        console.log('✅ FILE UPLOAD RESTRICTED:');
        console.log(`   Allowed extensions: ${ALLOWED_EXTENSIONS.join(', ')}`);
        console.log(`   Max size: ${MAX_SIZE / 1024 / 1024}MB`);
        console.log(`   photo.jpg (1MB): ${isFileAllowed('photo.jpg', 1024 * 1024)}`);
        console.log(`   shell.php (1KB): ${isFileAllowed('shell.php', 1024)}`);

        expect(isFileAllowed('photo.jpg', 1024 * 1024)).toBe(true);
        expect(isFileAllowed('shell.php', 1024)).toBe(false);
        expect(isFileAllowed('huge.jpg', 10 * 1024 * 1024)).toBe(false);
    });
});

// ============================================================================
// SUMMARY
// ============================================================================
describe('SUMMARY: Extended OWASP Coverage', () => {
    it('All extended cases covered', () => {
        const extendedCases = [
            'Case 11: API Security',
            'Case 12: Input Validation',
            'Case 13: Session Security',
            'Case 14: Error Handling',
            'Case 15: Timing Attacks',
            'Case 16: File Upload Security',
        ];

        console.log('\n✅ EXTENDED SECURITY CASES:');
        extendedCases.forEach((c, i) => {
            console.log(`   ${i + 11}. ${c}`);
        });

        expect(extendedCases).toHaveLength(6);
    });
});
