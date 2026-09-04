# GraphQL Attacks
> **Author:** MD MAHABUBUR RAHMAN

GraphQL is now the default API layer for modern web apps. Misconfigured GraphQL endpoints give up the entire schema — and often unlimited data/abuse.

## Quick triage
- Find endpoint: `/graphql`, `/api/graphql`, `/query`, `/v1/graphql`, `/gql`, `/graphiql`
- Send `{__typename}` to detect: `POST /graphql` with body `{"query":"{__typename}"}`
- Response contains `"data":{"__typename":"Query"}` → GraphQL confirmed.

## Files
| File | Content |
|------|---------|
| `graphql-payloads.txt` | Introspection, injection, mutations, batching, DoS payloads |

## Attack priority
1. **Introspection** enabled → dump entire schema (huge bounty lead).
2. **Batching / aliasing DoS** → request amplification → DoS.
3. **Auth bypass** on mutations (create/delete/update without token).
4. **IDOR on GraphQL** → fetch any object by ID.
5. **Injection inside queries** (SQLi/NoSQLi/command via args).
6. **Query depth / complexity abuse** → DoS.

## Tools
| Tool | Use |
|------|-----|
| GraphiQL app / Altair | interactive explorer |
| Burp + inql | auto-generate full CRUD tests from schema |
| `graphql-map` / `graphw00f` | fingerprint GraphQL server + protections |
| `clairvoyance` | get schema when introspection is blocked |
| `graphql-cop` | automated misconfig scanner |

## Reporting tip
Introspection + unauthenticated mutation access is often Critical/High. Show: (1) schema dump, (2) an unauth mutation that creates/modifies data, (3) an IDOR read.
