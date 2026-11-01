[![CI](https://github.com/gamai-io/gama-sandbox/actions/workflows/ci.yml/badge.svg)](https://github.com/gamai-io/gama-sandbox/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

# gama-sandbox

Isolation layer for AI agents that must run untrusted code: **filesystem + network gate without Docker**, plus a per-session sandbox harness with Docker/bwrap/srt fallback.

Two independent pieces, both dependency-light:

| File | What it does | Needs |
|---|---|---|
| `sandbox_srt.sh` | Runs a command under [Anthropic Sandbox Runtime](https://www.npmjs.com/package/@anthropic-ai/sandbox-runtime): no network by default, secrets unreadable, writes only cwd + `/tmp` | `srt` (npm), unprivileged user namespaces |
| `sessionbox/run.py` | Per-`sid` sandbox: Docker → bwrap → srt fallback, hard timeouts, snapshot/stop | Python 3.10+; Docker **or** bwrap **or** srt |

## Profiles (`sandbox_srt.sh`)

```bash
./sandbox_srt.sh offline  -- bash -lc "python3 untrusted.py"      # default: no net, secrets denied
./sandbox_srt.sh readonly -- cat /etc/passwd                      # no net, writes only /tmp
./sandbox_srt.sh net --env SRT_DOMAINS=api.github.com -- curl -s https://api.github.com
./sandbox_srt.sh audit    -- bash -lc "..."                       # diagnostics only, NOT a sandbox
```

Secrets denied by default: `~/.ssh`, `~/.aws`, `~/.config/gama*`, `/etc/shadow`, `**/.env`, `**/*.pem`, `**/*.key`, `id_rsa`, `id_ed25519`.

## sessionbox

```bash
echo '{"op":"start","sid":"job1","image":"python:3.12-slim"}' | python3 sessionbox/run.py
echo '{"op":"exec","sid":"job1","cmd":"python -c \"print(6*7)\""}' | python3 sessionbox/run.py
echo '{"op":"stop","sid":"job1"}' | python3 sessionbox/run.py
```

Guarantees: no network by default; only the per-sid workdir is exposed; every exec has a hard timeout; `stop` snapshots and deletes state; fail-closed on unknown sid/backend.

## Measured (MI250X cluster + x86 hosts)

- Firecracker microVM (reference): boot **1.846 s**, restore **2.286 ms** (≈native).
- gVisor `runsc` syscall overhead: **4–13×** vs native.
- `sandbox_srt.sh` itself adds only process startup + `srt` wrapper overhead.

## Limitations

- srt is **not** a container: shares the kernel; no GPU isolation; requires unprivileged userns/bwrap.
- `audit` profile is for diagnostics only.
- sessionbox Docker backend is not a hard multi-tenant boundary (kernel escape = host escape).

## License

Apache-2.0.
