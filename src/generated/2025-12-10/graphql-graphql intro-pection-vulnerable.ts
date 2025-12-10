/**
 * ⚠️ CASE 4: GRAPHQL INTROSPECTION - VULNERÁVEL
 * CVE: CWE-200
 * Gerado em 2025-12-10
 */

// 🔴 CÓDIGO VULNERÁVEL:
new ApolloServer({ introspection: true }); // Expõe schema

// Explicação: Este código é vulnerável a GraphQL Introspection
