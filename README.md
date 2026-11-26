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

Secrets denied by default: `~/.ssh`, `~/.aws`, `~/.config/gama*`, `**/.env`, `**/*.pem`, `**/*.key`, `id_rsa`, `id_ed25519`.

**Known limit, measured:** with srt 0.0.79 the `denyRead` entry for
`/etc/shadow` is not enforced (the file stays readable inside the srt sandbox);
the bwrap and Docker backends do not expose `/etc` at all. Do not run the sandbox
as root, and use bwrap/Docker when password hashes matter. This is reported
upstream, not papered over.

### Environment (`--env`) — sandboxed child only

`--env KEY=VAL` is **never exported** into the shell that starts `srt`. It is turned into an
`env KEY=VAL …` prefix that runs *inside* the sandbox, so the value exists only after bwrap has
applied the filesystem/network/namespace restrictions. `LD_PRELOAD`, `NODE_OPTIONS`, `PATH` and
friends therefore cannot execute code in the unsandboxed `srt`/`node`/`timeout` parent
(see `SECURITY.md`, fixed 2026-11-26; regression test `tests/test_env_isolation.sh`).

The wrapper also starts `srt` with a **minimal allow-list environment** (`PATH`, `HOME`, `USER`,
`LOGNAME`, `LANG`, `LC_ALL`, `LC_CTYPE`, `TERM`, `TZ`, `TMPDIR`). The sandboxed command does not
inherit the caller's environment, so pass what it needs explicitly:

```bash
./sandbox_srt.sh offline --env FOO=bar --env AWS_PROFILE=job -- bash -lc 'echo "$FOO"'
```

Malformed specs (`--env FOO`, `--env 1BAD=x`) are rejected before anything runs.


## sessionbox

```bash
echo '{"op":"start","sid":"job1","image":"python:3.12-slim"}' | python3 sessionbox/run.py
echo '{"op":"exec","sid":"job1","cmd":"python -c \"print(6*7)\""}' | python3 sessionbox/run.py
echo '{"op":"stop","sid":"job1"}' | python3 sessionbox/run.py
```

Guarantees: no network by default; only the per-sid workdir is exposed; every exec has a hard timeout; `stop` snapshots and deletes state; fail-closed on unknown sid/backend. The `bwrap`/`srt` backends run with a cleared/allow-listed environment, so the caller's variables (API keys, `LD_PRELOAD`, `NODE_OPTIONS`, …) do not reach the sandboxed process.

## Measured (MI250X cluster + x86 hosts)
> Note: measured on an internal lab (Firecracker + gVisor on MI250X/x86). The harness for those runs is **not shipped here**; treat the figures as indicative. What you can run locally is `sandbox_srt.sh`.

- Firecracker microVM (reference): boot **1.846 s**, restore **2.286 ms** (≈native).
- gVisor `runsc` syscall overhead: **4–13×** vs native.
- `sandbox_srt.sh` itself adds only process startup + `srt` wrapper overhead.

## Limitations

- srt is **not** a container: shares the kernel; no GPU isolation; requires unprivileged userns/bwrap.
- `audit` profile is for diagnostics only.
- sessionbox Docker backend is not a hard multi-tenant boundary (kernel escape = host escape).

## License

Apache-2.0.

## Why "no Docker" is the point (asked on AI Lounge, 24 Nov 2026)

Small teams want their agent walled off from the filesystem and the network and have **nobody to run
Docker**. `sandbox_srt.sh` gives them that with `srt`/bubblewrap and no daemon to babysit. Teams that
already operate Docker keep Docker — this is not a replacement argument.
