#!/usr/bin/env bash
# Regresija za CVE-klasu: `--env` je ranije eksportovan u RODITELJA (nesandboxovan
# srt/node/timeout proces), pa je LD_PRELOAD/NODE_OPTIONS/PATH izvrsavao kod van
# pijeska. Ovaj test dokazuje da:
#   (a) komanda UNUTAR pijeska vidi --env FOO=bar,
#   (b) roditelj (proces koji izvrsava srt) ga NE vidi,
#   (c) LD_PRELOAD se konzumira SAMO unutar pijeska (loader greska unutra, ne vani),
#   (d) nevalidan --env je odbijen.
#
# Radi bez instaliranog srt-a (fake srt biljezi svoje okruzenje). Ako je pravi
# srt dostupan, dodatno se izvrsi pravi LD_PRELOAD dokaz u pijesku.
set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "ok   - $*"; }
bad()  { FAIL=$((FAIL+1)); echo "FAIL - $*"; }
check(){ if eval "$2"; then ok "$1"; else bad "$1"; fi; }

TMP="$(mktemp -d /tmp/gama-srt-envtest.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT
SB=./sandbox_srt.sh

# ---------- fake srt: biljezi okruzenje RODITELJA, pa izvrsi -c u praznom env ----------
# Napomena: putanja je upisana u skriptu jer --env allow-list namjerno NE
# propusta FAKE_SRT_ENV iz okruzenja pozivaoca (to je i dokaz da fix radi).
mkdir -p "$TMP/bin"
cat > "$TMP/bin/srt" <<FAKE
#!/usr/bin/env bash
set -u
if [ "\${1:-}" = "--version" ]; then echo "9.9.9"; exit 0; fi
dump="$TMP/parent_env"; cmd=""
while [ \$# -gt 0 ]; do
  case "\$1" in
    --settings) shift 2 ;;
    -c) shift; cmd="\$1"; shift ;;
    *) shift ;;
  esac
done
env | sort > "\$dump"          # <-- ovo je okruzenje srt RODITELJA
env -i PATH=/usr/local/bin:/usr/bin:/bin bash -c "\$cmd"   # <-- emulacija djeteta
FAKE
chmod +x "$TMP/bin/srt"
export SRT_BIN="$TMP/bin/srt"

# ---------- (a)+(b) FOO unutra, nikad kod roditelja ----------
out=$(FOO=ambient-foo "$SB" offline --env FOO=bar -- bash -c 'printf "INSIDE=%s\n" "${FOO:-<unset>}"' 2>&1)
check "srt parent env dump exists"          '[ -s "$TMP/parent_env" ]'
check "child sees --env FOO=bar"            '[ "$(printf %s "$out" | grep -c "INSIDE=bar")" -eq 1 ]'
check "child eval happened"                 'printf %s "$out" | grep -q "INSIDE="'

check "srt parent env has NO FOO"           '! grep -q "^FOO=" "$TMP/parent_env"'
check "caller's ambient FOO not inherited"  '! grep -q "^FOO=" "$TMP/parent_env"'
check "test process itself never got FOO"   '[ -z "${FOO:-}" ]'

# ---------- (c) LD_PRELOAD: nikad u roditelju ----------
rm -f "$TMP/parent_env"
NODE_OPTIONS='--require /tmp/evil.js' LD_PRELOAD=/tmp/evil.so LD_AUDIT=/tmp/evil.so \
  "$SB" offline --env LD_PRELOAD=/nonexistent/evil.so -- /bin/true >"$TMP/out" 2>"$TMP/err" || true

check "srt parent env has NO LD_PRELOAD"    '! grep -q "^LD_PRELOAD=" "$TMP/parent_env"'
check "srt parent env has NO LD_AUDIT"      '! grep -q "^LD_AUDIT=" "$TMP/parent_env"'
check "srt parent env has NO NODE_OPTIONS"  '! grep -q "^NODE_OPTIONS=" "$TMP/parent_env"'
# loader poruka smije doci samo iz djeteta (fake srt je izvrsava u praznom env-u)
check "loader error appears (inside child)" 'grep -q "cannot be preloaded" "$TMP/err"'
check "wrapper did not fail on missing .so"  '[ -s "$TMP/out" -o -s "$TMP/err" ]'

# ---------- (d) nevalidan --env se odbija ----------
"$SB" offline --env FOO -- /bin/true >/dev/null 2>"$TMP/e1"; rc1=$?
"$SB" offline --env 1BAD=x -- /bin/true >/dev/null 2>"$TMP/e2"; rc2=$?
check "--env without '=' rejected"          '[ "$rc1" -ne 0 ] && grep -q "KEY=VAL" "$TMP/e1"'
check "--env bad var name rejected"         '[ "$rc2" -ne 0 ] && grep -q "nevalidan naziv" "$TMP/e2"'

unset SRT_BIN FAKE_SRT_ENV

# ---------- pravi srt (ako radi na ovoj masini): LD_PRELOAD samo unutra ----------
real_srt=""
for c in "$(command -v srt 2>/dev/null || true)" /usr/local/bin/srt /usr/bin/srt; do
  [ -n "$c" ] && [ -x "$c" ] || continue
  case "$("$c" --version 2>/dev/null | head -1)" in [0-9]*.[0-9]*) real_srt="$c"; break;; esac
done
if [ -n "$real_srt" ] && "$SB" offline -- /bin/true >/dev/null 2>&1; then
  if command -v cc >/dev/null 2>&1; then
    cat > "$TMP/leak.c" <<'C'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
__attribute__((constructor)) static void leak(void) {
    char comm[64] = "?"; int f = open("/proc/self/comm", 0);
    if (f >= 0) { ssize_t n = read(f, comm, 63); if (n > 0) { comm[n] = 0; comm[strcspn(comm, "\n")] = 0; } close(f); }
    int sh = (access("/root/.ssh/id_ed25519", R_OK) == 0);
    char l[256]; int n = snprintf(l, sizeof l, "RAN comm=%s can_read_ssh_key=%d\n", comm, sh);
    int m = open(getenv("LEAK_MARKER"), O_WRONLY|O_CREAT|O_APPEND, 0600);
    if (m >= 0) { ssize_t r = write(m, l, (size_t)n); (void)r; close(m); }
}
C
    if cc -shared -fPIC -O2 -o "$TMP/leak.so" "$TMP/leak.c" >/dev/null 2>&1; then
      rm -f "$TMP/marker"
      LEAK_MARKER="$TMP/marker" "$SB" offline \
        --env LD_PRELOAD="$TMP/leak.so" --env LEAK_MARKER="$TMP/marker" -- /bin/true >/dev/null 2>&1 || true
      if [ -s "$TMP/marker" ]; then
        ok "real srt: LD_PRELOAD ran inside the sandbox"
        check "real srt: parent (timeout/node/srt) never loaded it" \
              '! grep -Eq "comm=(timeout|node|srt|rg|socat)" "$TMP/marker"'
        check "real srt: inside could NOT read ~/.ssh key" \
              'grep -q "can_read_ssh_key=0" "$TMP/marker"'
      else
        bad "real srt: LD_PRELOAD never ran even inside (unexpected)"
      fi
    else
      echo "skip - real srt: no C compiler for leak.so"
    fi
  else
    echo "skip - real srt: no C compiler for leak.so"
  fi
  out=$("$SB" offline --env FOO=bar -- bash -c 'printf "R=%s\n" "${FOO:-<unset>}"' 2>/dev/null)
  check "real srt: child sees --env FOO=bar" '[ "$out" = "R=bar" ]'
else
  echo "skip - real srt not usable here (fake-srt coverage above still ran)"
fi

# ---------- sessionbox: ambijentalne tajne ne ulaze u pijesak ----------
if command -v bwrap >/dev/null 2>&1; then
  export SESSIONBOX_STATE_DIR="$TMP/sbstate" SESSIONBOX_WORK_ROOT="$TMP/sbwork" SESSIONBOX_BACKEND=bwrap
  printf '%s' '{"sid":"envtest1"}' | DEEPINFRA_API_KEY=leaked-123 python3 sessionbox/run.py start >"$TMP/sb1" 2>&1 || true
  printf '%s' '{"sid":"envtest1","cmd":"echo TOKEN=[${DEEPINFRA_API_KEY:-<unset>}]"}' \
    | DEEPINFRA_API_KEY=leaked-123 python3 sessionbox/run.py exec >"$TMP/sb2" 2>&1 || true
  printf '%s' '{"sid":"envtest1"}' | python3 sessionbox/run.py stop >/dev/null 2>&1 || true
  if grep -q '"backend": "bwrap"' "$TMP/sb2" 2>/dev/null; then
    check "sessionbox/bwrap: ambient API key NOT in sandbox" 'grep -q "TOKEN=\[<unset>\]" "$TMP/sb2"'
  else
    echo "skip - sessionbox/bwrap not usable here"
  fi
  unset SESSIONBOX_STATE_DIR SESSIONBOX_WORK_ROOT SESSIONBOX_BACKEND
else
  echo "skip - bwrap not installed"
fi

echo "----------------------------------------"
echo "passed=$PASS failed=$FAIL"
[ "$FAIL" -eq 0 ] && { echo "ENV_ISOLATION_OK"; exit 0; } || { echo "ENV_ISOLATION_FAILED"; exit 1; }
