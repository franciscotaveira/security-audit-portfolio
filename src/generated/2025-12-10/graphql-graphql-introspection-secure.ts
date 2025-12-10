/**
 * ✅ CASE 10: GRAPHQL INTROSPECTION - SEGURO
 * CVE: CWE-200
 * Gerado em 2025-12-10
 */

// ✅ CÓDIGO SEGURO:
new ApolloServer({ introspection: process.env.NODE_ENV !== "production" });

// Correção: Proteção contra GraphQL Introspection
