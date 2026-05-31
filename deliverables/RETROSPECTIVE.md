# Retrospective Document

Project: **AI-Powered Codebase Security Analyzer (`secanalyzer`)**

## Initial expectations

At the beginning, I expected the project to be mainly about building an AI-assisted code review tool. The initial idea was broad: use modern LLMs to help developers understand codebases, identify security risks, and reason about GitHub issues or pull requests.

The actual project became more security-engineering focused than expected. The central challenge was not simply calling an LLM. It was building a tool that could handle source code, credentials, GitHub data, prompt injection risk, dependency risk, and operational errors in a controlled way.

## Pivot from the first proposal

The project pivoted from a broad AI security-assistant concept into a local CLI security analyzer. That pivot happened because the original direction was too large for the course timeline and created too many unclear trust boundaries.

A hosted or general-purpose assistant would have required decisions about user accounts, server storage, uploaded repositories, shared logs, authorization, and long-term data retention. Those concerns would have distracted from the core security objective. A local CLI was a better fit because it kept the trust boundary clear: the user's machine is trusted, while GitHub and LLM providers are external services called only when the user explicitly asks.

The pivot also made the project more testable. A local CLI can be exercised with mocked network calls, deterministic scan fixtures, and simple CI gates.

## What went well

The MVP stayed coherent. The final tool has a clear purpose and a clean command model:

- `--scan` for deterministic repository inventory and static analysis;
- `--llm-report` for LLM-assisted codebase reporting;
- `--list-issues` for GitHub issue/PR visibility;
- `--analyze-issue` for focused issue or PR security review.

The security model also became stronger over time. The project now has path confinement, allowlisted file types, secret redaction, outbound prompt blocking, delimiter-wrapped untrusted data, schema validation, local operational logging, and CI security checks.

The documentation improved significantly. By the final release, the repository has a README, quickstart, deployment guide, security policy, technical report, security report, issue log, final report, and retrospective.

## Major challenges

### 1. Managing scope

The biggest challenge was resisting feature expansion. There were many possible directions: hosted dashboards, continuous scans, auto-fixes, richer GitHub project integration, SARIF output, SBOMs, and more providers. The project had to stay focused on a complete and demonstrable local tool.

### 2. Handling LLM risk honestly

Prompt injection and sensitive-data exfiltration are difficult problems. The project could not claim to solve them completely. Instead, it had to implement layered mitigations and document residual risk clearly. This was a useful lesson: a secure AI system needs boundaries, not just better prompts.

### 3. Rate limits and provider instability

LLM provider behavior was less predictable than normal local code. Google model availability and rate limiting created reliability problems. The project responded with retry logic, configurable model IDs, model-listing support, and formal issue tracking for remaining rate-limit work.

### 4. Final-release polish

The beta release was functional, but final release required a different standard. Documentation had to be organized, operations had to be observable, accepted risks had to be logged, and the final report had to tell the complete story instead of only describing the current code.

## How challenges were addressed

Scope was handled by returning to the M2 MVP and treating extra ideas as issue-log entries rather than release blockers.

LLM risk was handled by implementing defense in depth:

- untrusted data delimiters;
- prompt size budgets;
- pre-send secret scanning and aborts;
- schema validation;
- redaction warnings;
- no automatic code execution from model output.

Reliability was handled with retries, user-facing errors, mocked tests, CI gates, and operational logging.

Documentation was handled by separating guides from reports and creating a final `deliverables/` folder for submission artifacts.

## What I would do differently

If I restarted the project, I would define the final deliverables earlier. The code progressed steadily, but the final release required significant documentation packaging and report synthesis. Starting the final report structure earlier would have made the last milestone smoother.

I would also add adversarial test fixtures earlier. The system includes prompt-injection mitigations, but a dedicated malicious-payload test suite would make those controls easier to demonstrate.

I would consider adding a stronger local secret scanner earlier in the design. Regex redaction is useful, but high-entropy detection or an established local scanner would make the data-handling story stronger.

Finally, I would treat LLM provider limits as a first-class non-functional requirement from the start. Rate limits affected real usability and should be modeled like any other reliability constraint.

## Takeaways for future projects

The biggest takeaway is that AI features need conventional engineering discipline around them. Prompting is only one part of the system. The surrounding controls decide whether the product is safe and usable:

- what data is collected;
- what data is sent externally;
- what gets logged;
- what gets validated;
- what happens when a provider fails;
- what a human can audit later.

For future security tools, I would start with trust boundaries, abuse cases, and operational evidence before adding advanced AI behavior. That approach produces a smaller but more defensible system.

## Final reflection

This project ended up stronger because it became more constrained. The pivot to a local CLI made the system easier to reason about, easier to test, and easier to defend. The final result is not a complete replacement for a human security review, but it is a useful security-assistance tool with clear documentation, measurable validation, and honest residual-risk tracking.
