#!/usr/bin/env python3
"""sessionbox — per-sid sandbox harness plugin (stdin=args JSON, stdout=JSON).

Backends (auto): Docker -> bwrap -> srt.
  docker  per-sid container, --network none, read-only rootfs, only the sid
          workdir bind-mounted at /work, cap-drop ALL, no-new-privileges,
          pids/mem/cpu limits, tmpfs /tmp, uid 65534.
  bwrap   per-exec namespace (user/pid/net/uts/ipc/cgroup), ro /usr, rw workdir,
          tmpfs /tmp, die-with-parent; session state is the sid workdir.
  srt     same idea via Anthropic sandbox runtime with empty network allowlist.

Guarantees:
  * no network by default (no opt-in in this version)
  * host FS exposure is only the per-sid workdir (Docker: /work)
  * every exec has a hard timeout; on timeout Docker container is killed and
    restarted, bwrap children die with the namespace init
  * stop snapshots the workdir (tar.gz), removes container/processes and the
    workdir, and deletes state
  * fail-closed on unknown sid/backend, bad sid/image, too many sessions

Env overrides (tests): SESSIONBOX_STATE_DIR, SESSIONBOX_WORK_ROOT,
SESSIONBOX_SNAPSHOT_DIR, SESSIONBOX_BACKEND, SESSIONBOX_MAX_SESSIONS.
"""

import fcntl
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import time
from datetime import datetime, timezone

BASE = os.path.dirname(os.path.abspath(__file__))
STATE_DIR = os.environ.get("SESSIONBOX_STATE_DIR", os.path.join(BASE, "state"))
WORK_ROOT = os.environ.get("SESSIONBOX_WORK_ROOT", "/tmp/gama_sessionbox")
SNAP_DIR = os.environ.get("SESSIONBOX_SNAPSHOT_DIR", os.path.join(BASE, "snapshots"))
LOCK_PATH = os.path.join(BASE, ".sessionbox.lock")
MAX_SESSIONS = int(os.environ.get("SESSIONBOX_MAX_SESSIONS", "8"))

DEFAULT_IMAGE = "python:3.12-alpine"
SID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,39}$")
IMAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,127}$")
TIMEOUT_MAX = 45
CMD_MAX = 8192
OUT_CLIP = 8000
CONTAINER_PREFIX = "gama-sb-"
LABEL = "gama.sessionbox"
LABEL_SID = "gama.sessionbox.sid"
UID = "65534:65534"

SECRET_PATHS = (
    "/etc/gama-harness.env",
    "/etc/gama-hc-token",
    "/etc/gama-hc-token.env",
    "/root/.ssh",
    "/root/.aws",
    "/root/.config",
)


def emit(obj):
    sys.stdout.write(json.dumps(obj, ensure_ascii=False, sort_keys=True))
    sys.stdout.write("\n")
    return 0


def err(msg, **extra):
    out = {"ok": False, "err": str(msg)}
    out.update(extra)
    return emit(out)


def clip(text, limit=OUT_CLIP):
    if text is None:
        return ""
    if not isinstance(text, str):
        text = str(text)
    if len(text) <= limit:
        return text
    return text[:limit] + "\n...[skraceno %d znakova]" % (len(text) - limit)


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def state_path(sid):
    return os.path.join(STATE_DIR, sid + ".json")


def workdir_for(sid):
    return os.path.join(WORK_ROOT, sid, "work")


def load_state(sid):
    try:
        with open(state_path(sid), "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else None
    except (FileNotFoundError, ValueError):
        return None


def save_state(st):
    os.makedirs(STATE_DIR, exist_ok=True)
    tmp = state_path(st["sid"]) + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(st, fh, ensure_ascii=False, sort_keys=True)
    os.replace(tmp, state_path(st["sid"]))


def delete_state(sid):
    try:
        os.unlink(state_path(sid))
    except FileNotFoundError:
        pass


def count_sessions():
    try:
        return len([n for n in os.listdir(STATE_DIR) if n.endswith(".json")])
    except FileNotFoundError:
        return 0


class Lock:
    def __enter__(self):
        os.makedirs(STATE_DIR, exist_ok=True)
        self.fh = open(LOCK_PATH, "a+")
        fcntl.flock(self.fh.fileno(), fcntl.LOCK_EX)
        return self

    def __exit__(self, *exc):
        try:
            fcntl.flock(self.fh.fileno(), fcntl.LOCK_UN)
        finally:
            self.fh.close()
        return False


def run_argv(argv, timeout, cwd=None):
    t0 = time.time()
    try:
        proc = subprocess.run(
            argv,
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            text=True,
            errors="replace",
        )
        return {
            "rc": proc.returncode,
            "stdout": proc.stdout or "",
            "stderr": proc.stderr or "",
            "timed_out": False,
            "ms": int((time.time() - t0) * 1000),
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "rc": None,
            "stdout": (exc.stdout or "") if isinstance(exc.stdout, str) else "",
            "stderr": (exc.stderr or "") if isinstance(exc.stderr, str) else "",
            "timed_out": True,
            "ms": int((time.time() - t0) * 1000),
        }
    except FileNotFoundError as exc:
        return {"rc": None, "stdout": "", "stderr": str(exc), "timed_out": False, "ms": 0}


def docker_available():
    if not shutil.which("docker"):
        return False
    return run_argv(["docker", "version", "--format", "{{.Server.Version}}"], 5)["rc"] == 0


def bwrap_available():
    if not shutil.which("bwrap"):
        return False
    probe = [
        "bwrap", "--unshare-all", "--die-with-parent",
        "--ro-bind", "/usr", "/usr",
        "--symlink", "usr/bin", "/bin",
        "--symlink", "usr/lib", "/lib",
        "--symlink", "usr/lib64", "/lib64",
        "--proc", "/proc", "--dev", "/dev",
        "/usr/bin/true",
    ]
    return run_argv(probe, 5)["rc"] == 0


def select_backend():
    forced = (os.environ.get("SESSIONBOX_BACKEND") or "").strip().lower()
    checks = {"docker": docker_available, "bwrap": bwrap_available, "srt": lambda: bool(shutil.which("srt"))}
    if forced:
        if forced not in checks:
            return None, "nepoznat SESSIONBOX_BACKEND: %s" % forced
        if not checks[forced]():
            return None, "backend %s nije dostupan" % forced
        return forced, None
    for name in ("docker", "bwrap", "srt"):
        try:
            if checks[name]():
                return name, None
        except Exception:
            continue
    return None, "nijedan backend (docker/bwrap/srt) nije dostupan"


def container_name(sid):
    return CONTAINER_PREFIX + sid


def docker_inspect(name):
    res = run_argv(["docker", "inspect", "--format", "{{json .State}}", name], 10)
    if res["rc"] != 0:
        return None
    try:
        return json.loads(res["stdout"].strip())
    except ValueError:
        return None


def docker_rm(name):
    run_argv(["docker", "rm", "-f", name], 20)


def reap_orphans():
    """Remove sessionbox containers that have no matching state file."""
    res = run_argv(["docker", "ps", "-aq", "--filter", "label=%s=1" % LABEL], 10)
    if res["rc"] != 0:
        return []
    removed = []
    for cid in res["stdout"].split():
        if not cid:
            continue
        lab = run_argv(
            ["docker", "inspect", "--format",
             '{{index .Config.Labels "%s"}}' % LABEL_SID, cid], 10)
        sid = (lab["stdout"] or "").strip()
        if sid and os.path.exists(state_path(sid)):
            continue
        run_argv(["docker", "rm", "-f", cid], 20)
        removed.append(cid)
    return removed


def bwrap_argv(work, cmd):
    argv = [
        "bwrap", "--unshare-all", "--die-with-parent", "--new-session",
        "--ro-bind", "/usr", "/usr",
        "--symlink", "usr/bin", "/bin",
        "--symlink", "usr/lib", "/lib",
        "--symlink", "usr/lib64", "/lib64",
        "--proc", "/proc", "--ro-bind", "/proc/sys", "/proc/sys", "--dev", "/dev", "--tmpfs", "/tmp",
        "--bind", work, "/work", "--chdir", "/work",
        "--setenv", "PATH", "/usr/local/bin:/usr/bin:/bin",
        "--setenv", "HOME", "/tmp",
        "--setenv", "LANG", "C.UTF-8",
        "--setenv", "LC_ALL", "C.UTF-8",
        "sh", "-c", cmd,
    ]
    return argv


def srt_settings_path(sid):
    return os.path.join(STATE_DIR, "srt-%s.json" % sid)


def write_srt_settings(sid, work):
    os.makedirs(STATE_DIR, exist_ok=True)
    settings = {
        "filesystem": {
            "denyRead": list(SECRET_PATHS),
            "allowWrite": [work, "/tmp"],
            "denyWrite": [],
        },
        "network": {"allowedDomains": [], "deniedDomains": []},
    }
    path = srt_settings_path(sid)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(settings, fh)
    return path


def validate_sid(sid):
    if not isinstance(sid, str) or not SID_RE.match(sid):
        return "nevalidan sid (dozvoljeno: [A-Za-z0-9][A-Za-z0-9_.-]{0,39})"
    return None


def validate_image(image):
    if not isinstance(image, str) or not IMAGE_RE.match(image):
        return "nevalidan image"
    return None


def dir_bytes(path):
    total = 0
    try:
        for root, _dirs, files in os.walk(path):
            for name in files:
                try:
                    total += os.path.getsize(os.path.join(root, name))
                except OSError:
                    pass
    except OSError:
        return 0
    return total


def snapshot_workdir(sid, work):
    if not os.path.isdir(work):
        return {"path": None, "bytes": 0, "files": 0}
    files = 0
    for _root, _dirs, names in os.walk(work):
        files += len(names)
    if files == 0:
        return {"path": None, "bytes": 0, "files": 0}
    os.makedirs(SNAP_DIR, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = os.path.join(SNAP_DIR, "%s-%s.tar.gz" % (sid, ts))
    with tarfile.open(path, "w:gz") as tf:
        tf.add(work, arcname="work")
    return {"path": path, "bytes": os.path.getsize(path), "files": files}


def remove_workdir(sid):
    work = workdir_for(sid)
    root = os.path.realpath(WORK_ROOT)
    real = os.path.realpath(work)
    if real != root and real.startswith(root + os.sep) and os.path.basename(os.path.dirname(real)) == sid:
        shutil.rmtree(real, ignore_errors=True)
        return not os.path.exists(real)
    return False


def cmd_start(args):
    sid = args.get("sid")
    bad = validate_sid(sid)
    if bad:
        return err(bad)
    image = args.get("image") or DEFAULT_IMAGE
    bad = validate_image(image)
    if bad:
        return err(bad)

    backend, why = select_backend()
    if not backend:
        return err(why)

    with Lock():
        if backend == "docker":
            reap_orphans()
        st = load_state(sid)
        if st:
            if st.get("backend") == "docker":
                name = st.get("container") or container_name(sid)
                state = docker_inspect(name)
                if state and state.get("Running"):
                    return emit({"ok": True, "sid": sid, "exists": True, "created": False,
                                 "running": True, "backend": "docker", "container": name,
                                 "image": st.get("image"), "workdir": st.get("workdir"),
                                 "network": "none"})
                if state:
                    res = run_argv(["docker", "start", name], 30)
                    if res["rc"] == 0:
                        st["started_at"] = now_iso()
                        save_state(st)
                        return emit({"ok": True, "sid": sid, "exists": True, "created": False,
                                     "running": True, "backend": "docker", "container": name,
                                     "image": st.get("image"), "workdir": st.get("workdir"),
                                     "restarted": True, "network": "none"})
                # stale container gone -> recreate below
            else:
                work = st.get("workdir") or workdir_for(sid)
                os.makedirs(work, exist_ok=True)
                return emit({"ok": True, "sid": sid, "exists": True, "created": False,
                             "running": False, "backend": st.get("backend"),
                             "workdir": work, "network": "none",
                             "note": "per-exec namespace; state is the workdir"})

        if count_sessions() >= MAX_SESSIONS:
            return err("previse sesija (max %d); zaustavi neku prije nove" % MAX_SESSIONS)

        work = workdir_for(sid)
        os.makedirs(work, exist_ok=True)
        if backend == "docker":
            os.chown(work, 65534, 65534)
        st = {
            "sid": sid,
            "backend": backend,
            "workdir": work,
            "image": image if backend == "docker" else None,
            "created_at": now_iso(),
            "started_at": None,
            "last_exec": None,
            "last_rc": None,
        }
        if backend == "docker":
            name = container_name(sid)
            docker_rm(name)
            create = [
                "docker", "create", "--name", name,
                "--label", "%s=1" % LABEL,
                "--label", "%s=%s" % (LABEL_SID, sid),
                "--network", "none",
                "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges",
                "--pids-limit", "128",
                "--memory", "512m", "--memory-swap", "512m", "--cpus", "1",
                "--read-only",
                "--tmpfs", "/tmp:rw,nosuid,nodev,size=64m",
                "--mount", "type=bind,src=%s,dst=/work" % work,
                "--workdir", "/work",
                "--user", UID,
                "-e", "HOME=/tmp",
                "-e", "PATH=/usr/local/bin:/usr/bin:/bin",
                "-e", "LANG=C.UTF-8",
                image,
                "sh", "-c", "while :; do sleep 3600; done",
            ]
            res = run_argv(create, 45)
            if res["rc"] != 0:
                shutil.rmtree(work, ignore_errors=True)
                return err("docker create nije uspio: %s" % clip(res["stderr"], 1200))
            start = run_argv(["docker", "start", name], 30)
            if start["rc"] != 0:
                docker_rm(name)
                shutil.rmtree(work, ignore_errors=True)
                return err("docker start nije uspio: %s" % clip(start["stderr"], 1200))
            st["container"] = name
            st["started_at"] = now_iso()
            save_state(st)
            return emit({"ok": True, "sid": sid, "exists": False, "created": True,
                         "running": True, "backend": "docker", "container": name,
                         "image": image, "workdir": work, "network": "none",
                         "limits": {"pids": 128, "mem_mb": 512, "cpus": 1.0,
                                    "rootfs": "read-only", "tmpfs": "/tmp"}})

        if backend == "srt":
            st["settings"] = write_srt_settings(sid, work)
        save_state(st)
        return emit({"ok": True, "sid": sid, "exists": False, "created": True,
                     "running": False, "backend": backend, "workdir": work,
                     "network": "none",
                     "note": "per-exec namespace; state is the workdir"})


def docker_exec(sid, st, cmd, timeout_s):
    name = st.get("container") or container_name(sid)
    state = docker_inspect(name)
    if not state:
        return {"ok": False, "err": "container ne postoji", "sid": sid,
                "backend": "docker", "rc": None, "stdout": "", "stderr": ""}
    if not state.get("Running"):
        started = run_argv(["docker", "start", name], 20)
        if started["rc"] != 0:
            return {"ok": False, "err": "container nije pokrenut: %s" % clip(started["stderr"], 800),
                    "sid": sid, "backend": "docker", "rc": None, "stdout": "", "stderr": ""}

    argv = ["docker", "exec", "-w", "/work", "-e", "HOME=/tmp", name, "sh", "-c", cmd]
    res = run_argv(argv, timeout_s + 5)
    if res["timed_out"]:
        run_argv(["docker", "kill", name], 15)
        restarted = run_argv(["docker", "start", name], 25)
        return {"ok": False, "timed_out": True, "sid": sid, "backend": "docker",
                "rc": None, "stdout": clip(res["stdout"]), "stderr": clip(res["stderr"]),
                "ms": res["ms"], "timeout_s": timeout_s,
                "killed": True, "restarted": restarted["rc"] == 0,
                "err": "timeout: komanda ubijena, container restartovan"}
    return {"ok": res["rc"] == 0, "sid": sid, "backend": "docker", "container": name,
            "rc": res["rc"], "stdout": clip(res["stdout"]), "stderr": clip(res["stderr"]),
            "ms": res["ms"], "timed_out": False, "timeout_s": timeout_s}


def namespace_exec(sid, st, cmd, timeout_s):
    work = st.get("workdir") or workdir_for(sid)
    if not os.path.isdir(work):
        return {"ok": False, "err": "workdir ne postoji", "sid": sid,
                "backend": st.get("backend"), "rc": None, "stdout": "", "stderr": ""}
    backend = st.get("backend")
    if backend == "bwrap":
        argv = bwrap_argv(work, cmd)
    else:
        settings = st.get("settings") or srt_settings_path(sid)
        if not os.path.exists(settings):
            settings = write_srt_settings(sid, work)
            st["settings"] = settings
            save_state(st)
        argv = ["srt", "--settings", settings, "-c", cmd]
    res = run_argv(argv, timeout_s, cwd=work)
    if res["timed_out"]:
        return {"ok": False, "timed_out": True, "sid": sid, "backend": backend,
                "rc": None, "stdout": clip(res["stdout"]), "stderr": clip(res["stderr"]),
                "ms": res["ms"], "timeout_s": timeout_s,
                "err": "timeout: namespace init ubijen, djeca umiru s njim"}
    return {"ok": res["rc"] == 0, "sid": sid, "backend": backend,
            "rc": res["rc"], "stdout": clip(res["stdout"]), "stderr": clip(res["stderr"]),
            "ms": res["ms"], "timed_out": False, "timeout_s": timeout_s}


def cmd_exec(args):
    sid = args.get("sid")
    bad = validate_sid(sid)
    if bad:
        return err(bad)
    cmd = args.get("cmd")
    if not isinstance(cmd, str) or not cmd.strip():
        return err("cmd mora biti neprazan string")
    if len(cmd) > CMD_MAX:
        return err("cmd predugacak (max %d)" % CMD_MAX)
    t = args.get("timeout_s", 20)
    if not isinstance(t, int) or isinstance(t, bool) or t < 1 or t > TIMEOUT_MAX:
        return err("timeout_s mora biti cio broj 1..%d" % TIMEOUT_MAX)

    st = load_state(sid)
    if not st:
        return err("nepoznat sid (pokreni session_sandbox_start)")

    if st.get("backend") == "docker":
        res = docker_exec(sid, st, cmd, t)
    else:
        res = namespace_exec(sid, st, cmd, t)
    try:
        st["last_exec"] = now_iso()
        st["last_rc"] = res.get("rc")
        save_state(st)
    except OSError:
        pass
    return emit(res)


def cmd_stop(args):
    sid = args.get("sid")
    bad = validate_sid(sid)
    if bad:
        return err(bad)
    snap_flag = args.get("snapshot", True)
    if not isinstance(snap_flag, bool):
        return err("snapshot mora biti boolean")

    with Lock():
        st = load_state(sid)
        if not st:
            return err("nepoznat sid", sid=sid, exists=False)
        work = st.get("workdir") or workdir_for(sid)
        snap = snapshot_workdir(sid, work) if snap_flag else {"path": None, "bytes": 0, "files": 0}
        backend = st.get("backend")
        container_removed = True
        if backend == "docker":
            name = st.get("container") or container_name(sid)
            run_argv(["docker", "rm", "-f", name], 25)
            container_removed = docker_inspect(name) is None
        settings = st.get("settings")
        if settings:
            try:
                os.unlink(settings)
            except FileNotFoundError:
                pass
        work_removed = remove_workdir(sid)
        delete_state(sid)
        orphan = reap_orphans() if backend == "docker" else []
    return emit({"ok": True, "sid": sid, "stopped": True, "backend": backend,
                 "snapshot": snap["path"], "snapshot_bytes": snap["bytes"],
                 "snapshot_files": snap["files"],
                 "container_removed": container_removed,
                 "workdir_removed": work_removed,
                 "orphans_removed": len(orphan), "ts": now_iso()})


def cmd_status(args):
    sid = args.get("sid")
    bad = validate_sid(sid)
    if bad:
        return err(bad)
    st = load_state(sid)
    if not st:
        return emit({"ok": True, "sid": sid, "exists": False})
    work = st.get("workdir") or workdir_for(sid)
    out = {
        "ok": True,
        "sid": sid,
        "exists": True,
        "backend": st.get("backend"),
        "image": st.get("image"),
        "workdir": work,
        "workdir_bytes": dir_bytes(work),
        "created_at": st.get("created_at"),
        "last_exec": st.get("last_exec"),
        "last_rc": st.get("last_rc"),
        "network": "none",
    }
    if st.get("backend") == "docker":
        name = st.get("container") or container_name(sid)
        state = docker_inspect(name)
        out.update({
            "container": name,
            "running": bool(state and state.get("Running")),
            "state": state.get("Status") if state else "missing",
            "pid": state.get("Pid") if state else None,
            "started_at": state.get("StartedAt") if state else st.get("started_at"),
        })
    else:
        out.update({"running": False,
                    "note": "per-exec namespace; only the workdir persists"})
    return emit(out)


HANDLERS = {"start": cmd_start, "exec": cmd_exec, "stop": cmd_stop, "status": cmd_status}


def main(argv):
    if len(argv) < 2 or argv[1] not in HANDLERS:
        return err("upotreba: run.py <%s>" % "|".join(sorted(HANDLERS)))
    try:
        data = json.load(sys.stdin)
    except Exception as exc:
        return err("nevalidan JSON na stdin: %s" % exc)
    if not isinstance(data, dict):
        return err("ocekivan objekat na stdin")
    return HANDLERS[argv[1]](data)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
