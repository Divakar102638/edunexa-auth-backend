# EduNexa Authentication Backend — Non-production starter

This project is extracted from the corrected backend source supplied in the conversation. It is a starting implementation for the Catalyst authentication/session POC, not a production-ready SaaS backend.

## Files included

- Express server and Node.js 24 AppSail configuration
- Catalyst request-context adapter and current-user verifier
- Repositories for the five existing Catalyst tables
- Authentication/session routes, middleware, and utility modules
- Lightweight Node test suite

## Before running

1. Use a NON-PRODUCTION Catalyst project only.
2. Review the existing Catalyst schema. Required manual changes from the source: unique constraints on `users.catalystUserId`, `institutions.institutionId`, and `backend_sessions.sessionId`; add `backend_sessions.accessTokenVersion` as a number/integer defaulting to 1. Recommended searchable indexes: `institution_memberships.userId`, `backend_sessions.userId`, `backend_sessions.tokenFamilyId`. Do not recreate tables.
3. Copy `.env.example` to `.env` and set long random secrets locally. Never commit `.env` or share secret values in chat.
4. Install and test with Node.js 24: `npm ci`, `npm test`, `npm run dev`.
5. Verify Catalyst Authentication request context end-to-end before enabling `/auth/exchange`. A local unauthenticated request should fail safely.

## Important security review required before production

- Refresh-token rotation now uses a conditional ZCQL `UPDATE` against the stored refresh-token hash, followed by a read-back check, so only one rotation from a given hash should win. This relies on Catalyst applying the `WHERE` condition atomically; verify this with concurrent requests against a non-production project before enabling the flow.
- ZCQL values are restricted to identifier characters before interpolation. Query syntax, ROWID comparisons, table names, and returned row shapes still require verification against the actual Catalyst schema and a non-production project.
- Automated tests cover token/session claim checks, conditional refresh rotation logic, CSRF, ZCQL input rejection and pagination, production configuration, and Express security headers. They do not prove Catalyst authentication, database behavior, tenant data isolation, or cross-instance concurrency safety.
- The backend uses Zoho's modular `@zcatalyst/auth` and `@zcatalyst/datastore` packages. Unit tests cover the initialization adapter and repository behavior, but Catalyst request-context authentication and AppSail behavior must still be confirmed in a non-production integration.
- The deprecated `zcatalyst-sdk-node` package has been replaced by Zoho's modular SDK. Live Catalyst request-context, database, and concurrency behavior still require verification in a non-production project.
- Startup validation, generic error responses, cookie/CORS checks, and basic security headers are implemented; production deployment settings and operational logging still need review.

## Scope

This is only the authentication/session foundation. It does not yet implement the full EduNexa modules (students, fees, attendance, exams, transport, reports, subscriptions).
