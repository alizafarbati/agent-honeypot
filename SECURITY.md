# agent-honeypot — Security Policy

## Scope

This project is a **defensive** research tool: a honeypot that studies unauthorized LLM agents. It contains no exploit code, no real credentials, and no capability for offensive operation.

## Design guarantees

1. All honeypot responses are synthetic. No real host, service, credential, or dataset is contacted by any component.
2. The capture plane persists digests and structured fields only — raw argument text never reaches disk in the hot path.
3. Any configured analysis LLM receives only bounded, structured profiles — never raw attacker-controlled text.
4. Lure changes pass a validation gauntlet (self-monitor, benign-corpus FP gate, anti-fingerprint checks) and require explicit human promotion from shadow state.
5. Every privileged action is appended to a hash-chain audit ledger (`security/audit/ledger.mjs`).

## Reporting a security issue with this software

Open a GitHub issue marked `security` or contact the maintainers directly. Please include reproduction steps and expected vs. actual behavior.

## Ethics note

This tool is for defenders and researchers operating surfaces they own. Deploying deception against systems you do not own, or attempting to exfiltrate data from visiting agents beyond what is needed for fingerprinting, is out of scope and not supported by this project.
