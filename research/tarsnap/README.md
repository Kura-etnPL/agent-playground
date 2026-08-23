# Tarsnap bug-bounty audit

Status: active research. No bounty claim or vulnerability claim has been made.

## Target

- Upstream: `Tarsnap/tarsnap`
- Ref: current `master`, with the exact commit recorded in every run artifact
- Initial environment: Ubuntu 24.04 GitHub-hosted runner
- Instrumentation: AddressSanitizer and UndefinedBehaviorSanitizer

## Rules for this audit

1. Use only public source code and researcher-controlled local inputs.
2. Do not contact, probe, or modify the production Tarsnap service.
3. Do not publish a security-sensitive finding through this repository.
4. Check open and closed upstream issues before treating a result as new.
5. A report is not ready until the stock path and a negative control are both reproducible.
6. State limitations honestly; static suspicions without a production-code reproduction are not findings.

## Current pipeline

The isolated workflow at `.github/workflows/tarsnap-bounty-audit.yml`:

1. clones the current upstream `master`;
2. records its exact commit;
3. builds a sanitizer-instrumented client;
4. runs a known public crash as an environment control;
5. uploads source, binary, and logs as short-lived evidence.

The next phase consumes that exact snapshot for de-duplicated, offline input and error-path testing. Only a distinct, verified non-security bug will be submitted publicly upstream.
