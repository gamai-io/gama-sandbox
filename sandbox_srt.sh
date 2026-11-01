#!/usr/bin/env bash
# GAMA sandbox (srt / Anthropic Sandbox Runtime) - jedinstveni sloj izolacije.
# Zamjena/olaksanje za Docker gama_sandbox: OS-level fs+mreza gate bez kontejnera.
#
# Upotreba:
#   gama_sandbox_srt.sh <profil> [--env SRT_DOMAINS=a.com,b.com] -- <komanda...>
#   gama_sandbox_srt.sh offline -- bash -lc "python3 untrusted.py"
#   gama_sandbox_srt.sh net --env SRT_DOMAINS=api.github.com -- curl -s https://api.github.com
#   gama_sandbox_srt.sh readonly -- cat /etc/passwd
#
# Profili:
#   offline   = NEMA mreze, strogi fs (cita sve osim tajni), pise samo cwd + /tmp   [DEFAULT za skill/kod]
#   readonly  = NEMA mreze, pise SAMO /tmp (nista u repo)
#   net       = mreza SAMO na SRT_DOMAINS (comma-sep), strogi fs
#   audit     = NEMA blokada fs/mreze, ali SRT_DEBUG log (samo dijagnostika, NE koristiti za nepouzdan kod)
set -euo pipefail
: "${HOME:=/root}"   # HC shell / servisi mogu doci bez HOME (set -u bi pukao)
: "${USER:=root}"; : "${LOGNAME:=$USER}"

PROFILE="${1:-offline}"; shift || true

# opcije --env KEY=VAL prije "--"
EXTRA_ENV=()
while [ $# -gt 0 ]; do
  case "$1" in
    --env) shift; EXTRA_ENV+=("$1"); shift ;;
    --) shift; break ;;
    *) break ;;
  esac
done
[ $# -gt 0 ] || { echo "greska: nema komande. Primjer: gama_sandbox_srt.sh offline -- bash -lc 'echo hi'" >&2; exit 2; }

# nadji PRAVI Anthropic srt (neki cvorovi imaju drugi 'srt' u /usr/local/bin)
_NPMPFX="$(npm prefix -g 2>/dev/null || true)"
find_srt() {
  for c in "${SRT_BIN:-}" "$(command -v srt 2>/dev/null || true)" "$HOME/.npm-global/bin/srt" /opt/node22/bin/srt "${_NPMPFX:+$_NPMPFX/bin/srt}" /usr/local/bin/srt /usr/bin/srt; do
    [ -n "$c" ] && [ -x "$c" ] || continue
    v="$("$c" --version 2>/dev/null | head -1)"
    case "$v" in [0-9]*.[0-9]*) echo "$c"; return 0;; esac
  done
  return 1
}
SRT="$(find_srt)" || { echo "greska: Anthropic srt nije nadjen (npm i -g @anthropic-ai/sandbox-runtime)" >&2; exit 3; }
# osiguraj da srt koristi SVOJ node (npr. /opt/node22) a ne stariji sistemski
export PATH="$(dirname "$SRT"):$PATH"

SYSROOT="${GAMA_SRT_DIR:-/tmp/gama_srt}"; mkdir -p "$SYSROOT"
RUNID="$$-$RANDOM"
CFG="$SYSROOT/settings-$PROFILE-$RUNID.json"
trap 'rm -f "$CFG"' EXIT
DOMAINS="${SRT_DOMAINS:-}"

# deny liste (tajne nikad u pijesak)
DENY_READ='["~/.ssh","~/.aws","~/.config/gama","~/.config/gama*","/etc/gama-harness.env","/etc/shadow","**/.env","**/*.pem","**/*.key","**/id_ed25519","**/id_rsa"]'

case "$PROFILE" in
  offline)
    ALLOW_DOMAINS='[]'; DENY_DOMAINS='["*"]'
    ALLOW_WRITE='[".","/tmp"]'
    ;;
  readonly)
    ALLOW_DOMAINS='[]'; DENY_DOMAINS='["*"]'
    ALLOW_WRITE='["/tmp"]'
    ;;
  net)
    [ -n "$DOMAINS" ] || { echo "greska: profil net trazi SRT_DOMAINS (npr. --env SRT_DOMAINS=api.github.com)" >&2; exit 2; }
    ALLOW_DOMAINS=$(printf '%s' "$DOMAINS" | python3 -c 'import sys,json;print(json.dumps([x.strip() for x in sys.stdin.read().split(",") if x.strip()]))')
    DENY_DOMAINS='[]'
    ALLOW_WRITE='[".","/tmp"]'
    ;;
  audit)
    ALLOW_DOMAINS='[]'; DENY_DOMAINS='[]'
    DENY_READ='[]'; ALLOW_WRITE='[".","/tmp","/root","/etc","/usr"]'
    ;;
  *) echo "nepoznat profil: $PROFILE (offline|readonly|net|audit)" >&2; exit 2 ;;
esac

cat > "$CFG" <<JSON
{
  "network": { "allowedDomains": $ALLOW_DOMAINS, "deniedDomains": $DENY_DOMAINS },
  "filesystem": { "denyRead": $DENY_READ, "allowRead": [], "allowWrite": $ALLOW_WRITE, "denyWrite": [] }
}
JSON

for e in "${EXTRA_ENV[@]:-}"; do [ -n "$e" ] && export "$e"; done

# deterministički limiti (vrijeme + broj procesa); virtuelna memorija se NE dira (lomi node)
GAMA_SRT_TIMEOUT="${GAMA_SRT_TIMEOUT:-120}"
ulimit -t "$GAMA_SRT_TIMEOUT" 2>/dev/null || true
ulimit -u 512 2>/dev/null || true
exec timeout -k 2 "$GAMA_SRT_TIMEOUT" "$SRT" --settings "$CFG" -c "$(printf '%q ' "$@")"
