# Security policy

## Reporting a vulnerability
Email **security@gamai.io** (or info@gamai.io). Do not open a public issue for exploitable problems.
We aim to acknowledge within 72 hours.

## Scope
This repository ships code that may run with elevated trust. We follow least privilege:
- no secrets in the repository, logs, or error messages;
- destructive or irreversible actions must be gated (explicit approval or a deny-list);
- every automated action should be verifiable after the fact (evidence, not assertion).

## Environment handling (hardening, 2026-11-26)

`--env` previously ran `export "$kv"` in the wrapper shell before `exec srt`. That exported
caller-supplied variables into the **unsandboxed parent** (`bash` → `timeout` → `node`/`srt`), so a
supplied `LD_PRELOAD` (or `NODE_OPTIONS`, `LD_AUDIT`, `BASH_ENV`, `PATH`) was consumed by the dynamic
loader *before* any restriction existed — arbitrary code execution outside the sandbox.

Fixed by:

- never exporting `--env`; values are prepended as `env KEY=VAL …` to the command that runs inside
  the sandbox (`srt 0.0.79` has no `--setenv`, and bwrap restrictions are already active when that
  command starts);
- launching `srt` itself with `env -i` plus a small allow-list (`PATH`, `HOME`, `USER`, `LOGNAME`,
  locale, `TERM`, `TZ`, `TMPDIR`);
- rejecting malformed `--env` specs up front;
- `sessionbox/run.py`: `bwrap` now uses `--clearenv` and both namespace backends receive the same
  allow-list environment, so ambient secrets (`DEEPINFRA_API_KEY`, server passwords) no longer leak
  into a session (previously they did).

Behaviour change: the sandboxed command no longer inherits the caller's environment implicitly.
Pass required variables explicitly with `--env`. Regression coverage:
`tests/test_env_isolation.sh` (runs in CI via `tests/smoke.sh`); it fails on the pre-fix code.

## Supported versions
The latest release on `main` receives security fixes.

## Out of scope
Findings that require a compromised host, or that only affect unsupported forks.

## Known limit: /etc/shadow under srt

srt 0.0.79 does not enforce a `denyRead` entry for `/etc/shadow`; the file remains
readable inside that backend. bwrap and Docker do not mount `/etc`. Run the
sandbox as an unprivileged user and prefer bwrap/Docker when this matters.
