---
name: vuln-verification
description: Validate a vulnerability analysis report against a local source tree and return an evidence-based verification result. Use when an agent needs to read a security analysis report, inspect the repository, choose a realistic reproduction path, generate validation artifacts, execute them, and conclude with `confirmed`, `not_reproduced`, or `inconclusive`.
---

# Vulnerability Verification

Treat the report as a claim to test, not as a conclusion to repeat.

## Workflow

Follow this sequence unless the user explicitly narrows scope:

1. Read the report and extract the claim to verify.
2. Inspect the repository and runtime shape before choosing an execution path.
3. Write an audit notebook that captures the real source-to-sink path.
4. Generate validation artifacts that preserve the target logic.
5. Execute the chosen path and collect logs, exit status, and outputs.
6. Assign a verdict only after reviewing the real execution result.

Do not jump directly from the report to a conclusion.

## Step 1: Understand the claim

Extract and restate these items from the report:

- Vulnerability type
- Claimed source or external input
- Claimed sink or dangerous side effect
- Propagation path and intermediate transforms
- Sanitizer, validation, or defense logic
- Trigger conditions and attacker-controlled assumptions
- Theoretical payload or PoC hint
- Expected success signal

If the report is vague, derive missing details from the code before generating any artifact. Prefer concrete file paths, functions, routes, and data shapes over prose summaries.

## Step 2: Inspect the repository

Inspect the repository to determine the most realistic feasible path:

- Build and runtime files such as `Dockerfile`, `docker-compose.yml`, `Makefile`, `package.json`, `requirements.txt`, `pyproject.toml`, `go.mod`, `pom.xml`, or test configs
- Existing tests that already touch the claimed logic
- Web entry points, CLI entry points, library APIs, and scripts
- Required external services and obvious blockers such as databases, private services, or secrets

Choose one strategy:

- `full_env`: Use when the service can be started locally with reasonable effort and the real entry point is reachable.
- `native_test`: Use when the project has a usable test framework and the vulnerable logic can be exercised through the project’s own code.
- `minimal_harness`: Use when the first two are not practical but the true source-to-sink chain can still be preserved with only external I/O mocked.

Read [references/verification-rules.md](references/verification-rules.md) for strategy selection rules and verdict boundaries.

## Step 3: Write the audit notebook

Create `audit_notebook.md` before generating the validation artifact. Treat it as the source of truth for later code generation.

Record:

- Sink point with file path, function, and exact dangerous operation
- Source point with file path, function, and attacker-controlled input
- Propagation path from source to sink in order
- Every parsing step, validation step, sanitizer, regex, conditional branch, encoding conversion, and string concatenation that matters
- Every dependency that must be mocked and why it is safe to mock
- The exact success signal to check during execution

Do not omit intermediary logic just because it is long. If it lies on the claimed path, capture it.

## Step 4: Generate validation artifacts

Generate artifacts in the current working area, not as hand-wavy examples. Prefer one of these forms:

- `full_env`: startup script plus a driver script or request sequence
- `native_test`: a minimal project-native test file
- `minimal_harness`: a single-file harness that faithfully replays the source-to-sink path

Always generate:

- `audit_notebook.md`
- One executable validation artifact such as `reproduce.py`, `reproduce.sh`, or a native test file
- `run.sh` that runs the validation in one step

Rules:

- Preserve sanitizer, validation, parsing, and propagation logic.
- Mock only external I/O boundaries such as databases, queues, or network clients when necessary.
- Do not hardcode success.
- Do not write a script that asserts the report is correct before execution.
- Prefer assertions on concrete sink effects, returned values, emitted commands, rendered output, or thrown exceptions.

## Step 5: Execute and collect evidence

Run the generated artifact and capture:

- Executed command
- Exit status
- Key stdout and stderr
- Files, logs, or traces that demonstrate the outcome
- Whether the expected success signal appeared

If the first path fails for operational reasons, try a lower-cost strategy only when the repository evidence supports that fallback. Record why the fallback was necessary.

## Step 6: Assign the verdict

Return exactly one verdict:

- `confirmed`: The execution produced the expected vulnerability signal with actionable evidence.
- `not_reproduced`: The target path executed under the tested conditions, but the expected vulnerability signal did not occur.
- `inconclusive`: The environment, missing dependencies, permissions, or unresolved assumptions prevented a reliable judgment.

Base the verdict on execution evidence, not on report confidence alone.

## Output requirements

The final answer must include:

- The selected strategy
- The verdict
- A short explanation tied to execution evidence
- Absolute paths for `audit_notebook.md`, the validation artifact, and `run.sh`
- The command that was run
- Any blocker that forced `inconclusive` or fallback

If the user only asked for planning, stop before artifact generation and clearly say execution was not performed.

## Guardrails

- Start from the assumption that the report may be wrong.
- Prefer disproving a claim over confirming it with a weak shortcut.
- Do not skip directly to `minimal_harness` when `full_env` or `native_test` is practical.
- Do not convert operational failure into `not_reproduced`.
- Do not erase the distinction between theoretical plausibility and executed verification.
- When the repository exposes a code-aware agent or helper, use it to understand the path, but keep the final verdict grounded in executable evidence.
