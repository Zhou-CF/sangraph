# Reproduction System

## Goal
The reproduction system consumes vulnerability candidates produced by the analysis system and tries to confirm or refute them with executable evidence. Its objective is accurate validation, not maximum throughput. The system should prefer the most realistic reproduction path that is feasible for the target repository and fall back only when necessary.

## Inputs and Outputs
Primary inputs:
- repository path or checked-out target source
- structured vulnerability candidate from the analysis system
- patch metadata and code context when available

Required candidate fields:
- vulnerability type
- suspected source and sink
- vulnerable sanitizer or defense logic
- trigger conditions and controllable input assumptions
- expected success signal

Final outputs:
- `confirmed`: the vulnerability is reproduced with actionable evidence
- `not_reproduced`: the attempted path did not reproduce the issue under the tested conditions
- `inconclusive`: the system could not make a reliable judgment because the environment or assumptions were insufficient

Evidence bundle:
- generated artifacts such as scripts, tests, or harnesses
- execution logs and exit status
- concise reasoning about why the verdict was assigned

## Core Workflow
1. Reproduction feasibility scan
   - Inspect the target repository for `Dockerfile`, `docker-compose.yml`, `Makefile`, dependency manifests, startup scripts, and existing tests
   - Detect whether the project already has a practical execution path and whether it supports native tests

2. Strategy selection by difficulty
   - Preferred order is fixed:
     1. full environment build
     2. native test case generation
     3. minimal harness or reduced call-path execution
   - The system chooses the highest-confidence feasible strategy instead of forcing a single universal method

3. Reproduction specification generation
   - Turn the candidate into a concrete execution spec containing input payloads, target entry points, success signals, and failure signals
   - Keep this spec separate from execution so the system can explain its assumptions

4. Artifact generation and execution
   - `full_env`: build or start the target system with Docker, Compose, or the project's native startup path, then drive the real entry point
   - `native_test`: add a minimal test in the project's own test framework and exercise the true vulnerable logic, mocking only external I/O when necessary
   - `minimal_harness`: build the smallest runnable path to the sink when neither of the first two strategies is practical

5. Evidence collection and verdicting
   - Capture request and response traces, logs, exceptions, files, database effects, or command output
   - Assign `confirmed`, `not_reproduced`, or `inconclusive` based on predefined success and failure signals

## Implementation Direction
Phase 1 target:
- Implement the reproduction system as a separate second-stage module, not as a hard dependency of the analysis system
- Run locally with Docker and native test tooling rather than relying on a remote VM-first design
- Prefer realistic execution over broad automation whenever the target can be built locally

Execution policy:
- If the project environment is easy to build, prioritize full environment reproduction
- If full environment build is too heavy but the project has a usable test framework, generate native tests
- If neither is practical, fall back to a minimal harness

Artifact policy:
- Store generated reproduction artifacts, logs, and notes in a dedicated working area
- Keep strategy-specific outputs explicit so the final verdict can be audited later

Integration policy:
- The analysis system should emit a structured candidate that the reproduction system can consume directly
- Reproduction failures must not erase the analysis result; they only refine confidence and final status

## Constraints and Risks
- Some repositories depend on private services, secrets, or unavailable infrastructure, which may make full reproduction impossible
- Auto-generated tests must preserve real business logic and avoid over-mocking, or the result will not be trustworthy
- Minimal harness execution can validate a sink path but may be weaker than a full environment result
- Running arbitrary target projects requires isolation, careful timeout handling, and clear logging
- Dynamic reproduction may fail for operational reasons; the system must distinguish operational failure from security non-reproducibility

## Success Criteria
- The system can automatically classify a target into `full_env`, `native_test`, or `minimal_harness`
- At least one practical path exists to generate executable evidence for a vulnerability candidate
- The final verdict always includes both status and evidence, not just narrative reasoning
- The reproduction stage can improve confidence when successful and return `inconclusive` cleanly when the environment is not workable
- The implementation no longer depends on the current remote VM workflow as the default execution path
