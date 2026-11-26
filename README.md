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
4. Install and test with Node.js 24: `npm install`, `npm test`, `npm run dev`.
5. Verify Catalyst Authentication request context end-to-end before enabling `/auth/exchange`. A local unauthenticated request should fail safely.

## Important security review required before production

- Refresh-token rotation in the supplied implementation must be made atomic/conditional to prevent two concurrent refresh requests from both succeeding. A simple read-then-update is race-prone.
- Review ZCQL construction and escaping against the current Catalyst SDK; do not assume string escaping alone is sufficient for all inputs.
- Validate CSRF, cookie flags, CORS origins, and mobile-vs-browser token handling in real integration tests.
- Add startup validation for required secrets and production-safe error/log handling.
- The included tests cover token primitives only; they do not prove Catalyst auth, database behavior, tenant isolation, or concurrency safety.
- Confirm all Catalyst SDK methods and AppSail configuration against the current Catalyst docs and an actual non-production deployment.

## Scope

This is only the authentication/session foundation. It does not yet implement the full EduNexa modules (students, fees, attendance, exams, transport, reports, subscriptions).
