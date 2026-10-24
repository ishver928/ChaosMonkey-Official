"""Docker-backed isolation for the verification layer.

Threat model (see backend/README.md for the full writeup): this runs code the *user themselves
uploaded* to ChaosMonkey, inside an internal-only Docker network, non-root, read-only root FS,
all capabilities dropped, no new privileges, resource-limited, with a hard wall-clock timeout.
Docker is a strong but not perfect boundary (kernel-sharing container escapes exist); gVisor
(`runsc`) is used automatically when available for a stronger boundary, and this is never
presented as suitable for running code the user does not trust or does not own.

Nothing here ever binds to a non-loopback host interface or reaches outside the machine: the
Docker network created for each run has no gateway (`internal: true` equivalent via
`--internal`), so even if the sandboxed app tried to phone out, there is no route.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

RUNNER_PY_IMAGE = "chaosmonkey-runner-python:1"
RUNNER_NODE_IMAGE = "chaosmonkey-runner-node:1"
AGENT_DIR = Path(__file__).resolve().parent / "agent"
HARD_TIMEOUT_S = 45
APP_START_GRACE_S = 20


@dataclass
class DockerAvailability:
    available: bool
    reason: str = ""
    gvisor: bool = False


@dataclass
class SandboxRunResult:
    run_id: str
    status: str  # "ok" | "docker_unavailable" | "error"
    agent_output: dict = field(default_factory=dict)
    log: list[str] = field(default_factory=list)
    error: str = ""


_FIXED_DOCKER_CANDIDATES = [
    r"C:\Program Files\Docker\Docker\resources\bin\docker.exe",
    r"C:\Program Files\Docker\Docker\resources\docker.exe",
]


def _docker_bin() -> str | None:
    """Locate the docker CLI. ``shutil.which`` covers the common case, but a backend launched
    from an IDE/tool that doesn't inherit the user's full shell PATH (Docker Desktop installs
    put ``docker.exe`` in its own resources dir, which isn't always on PATH) would otherwise
    report "unavailable" even though Docker Desktop is installed and running."""
    found = shutil.which("docker")
    if found:
        return found
    candidates = [Path(c) for c in _FIXED_DOCKER_CANDIDATES]
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        candidates.append(Path(local_app_data) / "Programs" / "DockerDesktop" / "resources" / "bin" / "docker.exe")
    for c in candidates:
        if c.is_file():
            return str(c)
    return None


def check_docker() -> DockerAvailability:
    binp = _docker_bin()
    if binp is None:
        return DockerAvailability(available=False, reason="docker executable not found on PATH")
    try:
        r = subprocess.run([binp, "info", "--format", "{{json .}}"], capture_output=True,
                            text=True, timeout=10)
    except Exception as exc:
        return DockerAvailability(available=False, reason=f"docker info failed: {exc}")
    if r.returncode != 0:
        return DockerAvailability(available=False, reason=(r.stderr or "docker engine not reachable").strip()[:300])
    gvisor = "runsc" in r.stdout
    return DockerAvailability(available=True, gvisor=gvisor)


def _run(cmd: list[str], timeout: int, log: list[str]) -> subprocess.CompletedProcess:
    log.append("$ " + " ".join(cmd))
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def _hardening_flags(read_only_root: bool = True) -> list[str]:
    """Flags shared by every sandboxed container. ``--network`` is added separately by the
    caller (each run gets its own network, created/torn down per run)."""
    flags = [
        "--user", "10001:10001",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--pids-limit", "128",
        "--memory", "384m",
        "--cpus", "1",
    ]
    if read_only_root:
        flags += ["--read-only", "--tmpfs", "/tmp:rw,size=64m"]
    return flags


def run_verification(run_id: str, project_dir: Path, image: str, run_cmd: list[str],
                      app_port: int, plan: dict, docker_bin: str, gvisor: bool = False) -> SandboxRunResult:
    """Spin up an internal-only network, launch the app container, then the probe-agent
    container on the same network, collect the agent's JSON, and tear everything down."""
    log: list[str] = []
    net_name = f"cm-sbx-{run_id}"
    app_name = f"cm-app-{run_id}"
    agent_name = f"cm-agent-{run_id}"
    ro_copy = None
    data_dir = None
    try:
        _run([docker_bin, "network", "create", "--internal", net_name], 15, log)

        # Read-only copy of the project so the container mount can never be written back to disk.
        ro_copy = Path(tempfile.mkdtemp(prefix="cm_sbx_ro_"))
        shutil.copytree(project_dir, ro_copy, dirs_exist_ok=True)

        # A small read-write scratch dir, shared (via a host bind mount) between the app
        # container and the probe-agent container, for the one thing a read-only app
        # legitimately needs to write at run time: its own SQLite file. This is NOT the
        # project mount — the project itself stays read-only the whole time.
        data_dir = Path(tempfile.mkdtemp(prefix="cm_sbx_data_"))

        runtime_flags = ["--runtime", "runsc"] if gvisor else []

        app_cmd = [
            docker_bin, "run", "-d", "--rm", "--name", app_name,
            "--network", net_name,
            *runtime_flags,
            *_hardening_flags(read_only_root=True),
            "-v", f"{ro_copy}:/project:ro",
            "-v", f"{data_dir}:/data:rw",
            "-w", "/project",
        ]
        for k, v in plan.get("env", {}).items():
            app_cmd += ["-e", f"{k}={v}"]
        app_cmd += ["-e", "CM_DB_DIR=/data"]
        if image == RUNNER_NODE_IMAGE:
            app_cmd += ["-e", "NODE_PATH=/node_modules"]
        app_cmd += [image, *run_cmd]
        r = _run(app_cmd, 20, log)
        if r.returncode != 0:
            return SandboxRunResult(run_id=run_id, status="error", log=log,
                                     error=f"failed to start app container: {r.stderr.strip()[:500]}")

        _wait_for_log_or_sleep(docker_bin, app_name, log)

        # The app and probe-agent are separate containers; "localhost" inside the agent
        # container means the agent itself. Resolve the app by its container name, which the
        # shared user-defined network resolves via Docker's embedded DNS.
        plan = {**plan, "target_host": app_name}
        plan_path = ro_copy / "_cm_plan.json"
        plan_path.write_text(json.dumps(plan), encoding="utf-8")

        agent_cmd = [
            docker_bin, "run", "--rm", "--name", agent_name,
            "--network", net_name,
            *runtime_flags,
            *_hardening_flags(read_only_root=True),
            "-v", f"{AGENT_DIR}:/agent:ro",
            "-v", f"{ro_copy}:/project:ro",
            "-v", f"{data_dir}:/data:ro",
            "-w", "/agent",
            RUNNER_PY_IMAGE, "python", "/agent/cm_agent.py", "/project/_cm_plan.json",
        ]
        r2 = _run(agent_cmd, HARD_TIMEOUT_S, log)
        if r2.returncode != 0 and not r2.stdout.strip():
            return SandboxRunResult(run_id=run_id, status="error", log=log,
                                     error=f"probe agent failed: {r2.stderr.strip()[:800]}")
        try:
            out = json.loads(r2.stdout.strip().splitlines()[-1]) if r2.stdout.strip() else {}
        except json.JSONDecodeError:
            out = {"error": "agent produced non-JSON output", "raw": r2.stdout[:500]}
        return SandboxRunResult(run_id=run_id, status="ok", agent_output=out, log=log)
    except subprocess.TimeoutExpired:
        return SandboxRunResult(run_id=run_id, status="error", log=log, error="hard timeout exceeded")
    except Exception as exc:
        return SandboxRunResult(run_id=run_id, status="error", log=log, error=f"{type(exc).__name__}: {exc}")
    finally:
        subprocess.run([docker_bin, "rm", "-f", agent_name], capture_output=True, timeout=10)
        subprocess.run([docker_bin, "rm", "-f", app_name], capture_output=True, timeout=10)
        subprocess.run([docker_bin, "network", "rm", net_name], capture_output=True, timeout=10)
        if ro_copy is not None:
            shutil.rmtree(ro_copy, ignore_errors=True)
        if data_dir is not None:
            shutil.rmtree(data_dir, ignore_errors=True)


def _wait_for_log_or_sleep(docker_bin: str, app_name: str, log: list[str]) -> None:
    """Give the app container a moment to bind its port before the probe agent connects.
    The agent itself also retries on connect failure, so this is a best-effort head start."""
    deadline = time.time() + APP_START_GRACE_S
    while time.time() < deadline:
        r = subprocess.run([docker_bin, "inspect", "-f", "{{.State.Running}}", app_name],
                            capture_output=True, text=True, timeout=5)
        if r.stdout.strip() == "true":
            time.sleep(1.0)
            return
        time.sleep(0.5)
    log.append(f"warning: {app_name} did not report Running within {APP_START_GRACE_S}s")


def new_run_id() -> str:
    return uuid.uuid4().hex[:12]
