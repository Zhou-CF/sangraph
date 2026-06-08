# Analysis System

## Goal
The analysis system takes a repository and a security patch as input, extracts the core sanitizer or defense logic from the patch, retrieves similar historical vulnerability cases with RAG, and uses LLM-based comparison plus source-level verification to decide whether the patched code still contains a real vulnerability. The main objective is variant analysis and false-positive reduction, not whole-repository blind scanning.

## Inputs and Outputs
Primary inputs:
- `repo_path`: local path of the target repository
- `patch_path`: patch file path; this is the standard entry point

Core intermediate artifacts:
- `sanitizer_code`: defense code extracted from the patch and source context
- `sanitizer_logic`: structured description of the sanitizer behavior
- `sanitizer_logic_str`: normalized text used for retrieval
- `rag_search_result`: similar historical cases from the vulnerability knowledge base
- `full_analysis_result`: comparison report between target code and retrieved cases

Final outputs:
- structured vulnerability judgment (`is_real_vuln`, `is_vuln`)
- reasoning report for the decision
- optional cross-verification result after entry/source-code review

## Core Workflow
1. Patch-driven sanitizer extraction
   - Read the patch from `patch_path`
   - Use the code-aware agent to inspect the repository at `repo_path`
   - Extract the minimal sanitizer or defense code that represents the fix

2. Sanitizer logic structuring
   - Convert the extracted defense code into structured fields such as actions, details, and natural-language logic
   - Normalize the logic into a retrieval-friendly string

3. RAG retrieval over vulnerability knowledge
   - Query the Milvus-backed knowledge base with sanitizer logic and sanitizer code
   - Retrieve similar historical cases, including CVE/CWE context, vulnerable snippets, unsafe logic descriptions, and bypass PoCs

4. Differential vulnerability analysis
   - Compare the target sanitizer against retrieved unsafe patterns
   - Determine whether the new code still shares the same bypassable weakness or incomplete defense logic

5. Review and source-level cross-verification
   - Run a second-stage review model to filter weak or low-confidence findings
   - If the candidate is still considered real, inspect entry-point/source-code context and re-check the claim against the actual code path

6. Structured result generation
   - Convert the final analysis into a stable schema for downstream consumers

## Implementation Direction
Phase 1 target:
- Run the main analysis chain locally through Docker Compose
- Keep Milvus as a service container rather than switching to Milvus Lite
- Use environment variables for Milvus connection and model credentials
- Preserve the current patch -> sanitizer -> RAG -> judgment workflow

Required engineering changes:
- Replace hardcoded Milvus host, token, VM credentials, and other environment-specific values with configuration
- Normalize prompt path handling so local execution does not depend on external directory layouts
- Keep the Milvus server-side design with hybrid retrieval, sparse/dense indexes, and BM25-related features where supported
- Treat `opencode` and external model providers as explicit runtime dependencies
- Decouple dynamic reproduction logic from the main analysis path so the analysis system can run independently

Deployment shape:
- `app` container for Python analysis code
- `milvus` container for the vulnerability knowledge base
- `.env` or equivalent runtime config for LLM, embedding, and Milvus settings

## Constraints and Risks
- The current prototype depends on external LLM or embedding services; analysis quality and runtime stability depend on those services
- Retrieval quality depends on the quality and normalization of stored vulnerability cases
- The current codebase contains hardcoded paths and host information that must be removed before the system is portable
- Patch-based extraction works best when the patch clearly contains defense logic; low-signal patches may reduce extraction accuracy
- Source-aware steps that depend on `opencode` or similar tools need a reproducible installation path inside the containerized environment

## Success Criteria
- A local Docker Compose deployment can run the analysis system end-to-end on a target patch
- The system accepts `repo_path` and `patch_path` and produces structured vulnerability output
- Milvus retrieval works through configuration rather than hardcoded remote addresses
- The system can explain why a candidate vulnerability is considered real, not real, or uncertain
- The analysis system can run without invoking the reproduction subsystem
