# Verification Rules

Use these rules to keep validation results trustworthy and consistent.

## Strategy selection

Choose `full_env` when:

- The repository has a clear startup path.
- Required dependencies are local or containerizable.
- The vulnerable behavior is easiest to observe through the real service boundary.

Choose `native_test` when:

- The repository already has a test runner.
- The claimed logic is in a library, handler, helper, or component that tests can call directly.
- Writing a small test is cheaper and more trustworthy than booting the full stack.

Choose `minimal_harness` when:

- Full startup is blocked by heavy or unavailable infrastructure.
- A project-native test path is absent or impractical.
- The source-to-sink path can still be reproduced without mocking core business logic.

Prefer the highest-confidence feasible strategy, not the most ambitious one.

## Mocking rules

Allowed mocks:

- Database transport
- Network transport
- Message queues
- Filesystem or external service adapters

Disallowed mocks:

- Sanitizers
- Validation logic
- Parsing and decoding steps
- Branch conditions on the vulnerable path
- String construction or path construction that is part of the claim

Only mock what sits outside the security-relevant propagation path.

## Verdict boundaries

Return `confirmed` when:

- The payload reaches the sink in the unsafe form described by the claim, or
- The targeted unsafe effect is observed directly, or
- A project-native assertion proves the defense is bypassed

Return `not_reproduced` when:

- The intended path ran successfully, and
- The expected vulnerability signal did not appear under the tested conditions

Return `inconclusive` when:

- The service or test environment could not be started reliably
- Required secrets, fixtures, or infrastructure were missing
- The entry point or vulnerable path could not be reached
- Timeouts, permissions, or dependency issues prevented reliable execution

## Evidence expectations

The evidence bundle should be enough for another engineer to audit the result quickly:

- Exact command run
- Exit code
- Relevant output excerpt
- Absolute file paths for generated artifacts
- One short statement tying the evidence to the verdict
