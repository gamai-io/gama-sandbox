#!/usr/bin/env bash
# GAMA sandbox (srt / Anthropic Sandbox Runtime) - jedinstveni sloj izolacije.
# Zamjena/olaksanje za Docker gama_sandbox: OS-level fs+mreza gate bez kontejnera.
#
# Upotreba:
#   gama_sandbox_srt.sh <profil> [--env KEY=VAL]... -- <komanda...>
#   gama_sandbox_srt.sh offline -- bash -lc "python3 untrusted.py"
#   gama_sandbox_srt.sh net --env SRT_DOMAINS=api.github.com -- curl -s https://api.github.com
#   gama_sandbox_srt.sh readonly -- cat /etc/passwd
#
# Profili:
#   offline   = NEMA mreze, strogi fs (cita sve osim tajni), pise samo cwd + /tmp   [DEFAULT za skill/kod]
#   readonly  = NEMA mreze, pise SAMO /tmp (nista u repo)
#   net       = mreza SAMO na SRT_DOMAINS (comma-sep), strogi fs
#   audit     = NEMA blokada fs/mreze, ali SRT_DEBUG log (samo dijagnostika, NE koristiti za nepouzdan kod)
#
# BEZBJEDNOST --env (v2, 2026-11-26):
#   --env KEY=VAL se NIKAD ne exportuje u ovaj shell. Prosljedjuje se kao
#   `env KEY=VAL ... <komanda>` unutar pijeska, tj. vidi ga samo sandboxovano
#   dijete. Ranije je `export` u roditelju znacio da LD_PRELOAD/NODE_OPTIONS/
#   PATH zavrse u nesandboxovanom `srt`/`timeout`/`node` procesu prije bilo
#   kakve restrikcije = izvrsavanje koda van pijeska.
#
#   Ovaj shell pokrece `srt` sa MINIMALNIM (allow-list) okruzenjem preko
#   `env -i`, pa ni naslijedjene varijable (LD_*, NODE_OPTIONS, BASH_ENV,
#   GITHUB_TOKEN ...) ne ulaze u roditelja niti u pijesak. Sta treba unutra -
#   posalji eksplicitno sa --env.
set -euo pipefail
: "${HOME:=/root}"   # HC shell / servisi mogu doci bez HOME (set -u bi pukao)
: "${USER:=root}"; : "${LOGNAME:=$USER}"

PROFILE="${1:-offline}"; shift || true

die() { echo "greska: $*" >&2; exit 2; }

# opcije --env KEY=VAL prije "--" (cuva se za DIJETE, nikad se ne exportuje)
declare -a ENV_PAIRS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --env)
      shift || die "--env trazi KEY=VAL"
      spec="${1:-}"
      [ -n "$spec" ] || die "--env trazi KEY=VAL (prazno)"
      case "$spec" in
        *=*) : ;;
        *) die "--env trazi KEY=VAL (dobijeno: '$spec')" ;;
      esac
      key="${spec%%=*}"
      [ -n "$key" ] || die "--env: naziv varijable je prazan ('$spec')"
      case "$key" in
        [A-Za-z_]*) : ;;
        *) die "--env: nevalidan naziv varijable '$key' (dozvoljeno: [A-Za-z_][A-Za-z0-9_]*)" ;;
      esac
      case "$key" in
        *[!A-Za-z0-9_]*) die "--env: nevalidan naziv varijable '$key' (dozvoljeno: [A-Za-z_][A-Za-z0-9_]*)" ;;
      esac
      ENV_PAIRS+=("$spec")
      shift ;;
    --) shift; break ;;
    *) break ;;
  esac
done
[ $# -gt 0 ] || die "nema komande. Primjer: gama_sandbox_srt.sh offline -- bash -lc 'echo hi'"

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
SRT_DIR="$(dirname "$SRT")"

SYSROOT="${GAMA_SRT_DIR:-/tmp/gama_srt}"; mkdir -p "$SYSROOT"
RUNID="$$-$RANDOM"
CFG="$SYSROOT/settings-$PROFILE-$RUNID.json"
trap 'rm -f "$CFG"' EXIT

# SRT_DOMAINS: iz naseg (pozivacevog) okruzenja ILI iz --env SRT_DOMAINS=...
DOMAINS="${SRT_DOMAINS:-}"
for _kv in "${ENV_PAIRS[@]:-}"; do
  case "$_kv" in
    SRT_DOMAINS=*) [ -n "$DOMAINS" ] || DOMAINS="${_kv#SRT_DOMAINS=}" ;;
  esac
done

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

# --env ide SAMO u dijete: `env KEY=VAL ... <komanda>` izvrsava se UNUTAR pijeska.
# (srt 0.0.79 nema --setenv; ovako vrijednosti nastaju tek poslije bwrap-a)
if [ ${#ENV_PAIRS[@]} -gt 0 ]; then
  set -- env "${ENV_PAIRS[@]}" "$@"
fi

# deterministički limiti (vrijeme + broj procesa); virtuelna memorija se NE dira (lomi node)
GAMA_SRT_TIMEOUT="${GAMA_SRT_TIMEOUT:-120}"
ulimit -t "$GAMA_SRT_TIMEOUT" 2>/dev/null || true
ulimit -u 512 2>/dev/null || true

# Minimalno okruzenje za srt roditelja (allow-list, ne deny-list): sprijeci da
# naslijedjeni LD_PRELOAD/LD_AUDIT/NODE_OPTIONS/BASH_ENV/... izvrsavaju kod u
# nesandboxovanom `srt`/`node`/`timeout` procesu. Nista od pozivaoca ne prolazi
# implicitno; sandboxirana komanda dobija samo ovo + eksplicitne --env parove.
NODE_BIN="$(command -v node 2>/dev/null || true)"
PARENT_PATH="$SRT_DIR:${NODE_BIN:+$(dirname "$NODE_BIN"):}/usr/local/bin:/usr/bin:/bin"
declare -a P_ENV=("PATH=$PARENT_PATH" "HOME=$HOME" "USER=$USER" "LOGNAME=$LOGNAME")
for _v in LANG LC_ALL LC_CTYPE TERM TZ TMPDIR TEMP TMP; do
  eval "_val=\${${_v}:-}"
  [ -n "$_val" ] && P_ENV+=("$_v=$_val")
done

exec env -i "${P_ENV[@]}" timeout -k 2 "$GAMA_SRT_TIMEOUT" "$SRT" --settings "$CFG" -c "$(printf '%q ' "$@")"
