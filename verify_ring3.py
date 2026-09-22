"""
Ring 3 verification for the company-agent-python-hardened template.

Opens a sandbox from the built template and probes the file system
boundary from inside it, as the agent account, the same way a compromised
agent would. Every check asserts an OS level outcome. None of them ask
the model to cooperate. A sandbox whose controls can only be checked by
asking the agent nicely is not a sandbox.

Run after building template.py and before publishing:
    E2B_API_KEY=... python verify_ring3.py

Exits non-zero on the first failed control.

License: MIT
"""
import os
import shlex
import sys

from e2b import CommandExitException, Sandbox

from agent_sandbox import HARDEN_CMD

TEMPLATE = "company-agent-python-hardened"
WORKSPACE = "/workspace"
REFERENCE = "/srv/reference"
AGENT_USER = "agent"

results = []


def check(name: str, cmd: str, want_exit: int, sandbox) -> bool:
    """want_exit 0 means the command must succeed, non zero means the
    control must refuse it. A control that silently permits a write is
    the failure this catches."""
    try:
        sandbox.commands.run(cmd, timeout=30)
        got = 0
    except CommandExitException as e:
        got = e.exit_code
    ok = (got == 0) if want_exit == 0 else (got != 0)
    results.append((ok, name, f"exit={got}"))
    return ok


def main() -> int:
    if not os.environ.get("E2B_API_KEY"):
        print("set E2B_API_KEY")
        return 2

    sbx = Sandbox.create(
        template=TEMPLATE,
        timeout=180,
        network={"deny_out": lambda ctx: [ctx.all_traffic]},
    )
    try:
        # Apply the same session start hardening the harness applies.
        # E2B's configuration script runs after the template's layers and
        # makes /usr/local and /code world writable, so a template-only
        # check would pass while the live sandbox stayed open.
        sbx.commands.run(f"bash -lc {shlex.quote(HARDEN_CMD)}",
                         user="root", timeout=60)
        # Identity. Everything below is meaningless if the agent is root
        # or is an account that can become root.
        who = sbx.commands.run("whoami", timeout=30).stdout.strip()
        results.append((who == AGENT_USER, "runs as the agent account",
                        f"whoami={who}"))
        check("agent cannot sudo", "sudo -n true", 1, sbx)
        groups = sbx.commands.run(f"id -nG {AGENT_USER}", timeout=30).stdout.split()
        privileged = {"sudo", "wheel", "root", "admin", "adm"}
        bad = privileged.intersection(groups)
        results.append((not bad, "agent holds no privileged group",
                        f"groups={' '.join(groups)}"))

        # The one writable location.
        check("workspace is writable", f"touch {WORKSPACE}/probe", 0, sbx)

        # Reference material is read only and, more importantly, cannot be
        # removed. Ownership of the parent is what makes that true.
        check("reference docs not writable",
              f"touch {REFERENCE}/docs/probe", 1, sbx)
        check("reference docs not removable",
              f"rm -rf {REFERENCE}/docs", 1, sbx)
        check("reference tree not chmod-able",
              f"chmod -R 777 {REFERENCE}", 1, sbx)

        # Persistence through login files. E2B runs commands via bash -l,
        # so a writable dotfile would execute on every later command.
        check("cannot overwrite .bashrc",
              f"echo evil >> /home/{AGENT_USER}/.bashrc", 1, sbx)
        check("cannot create new dotfiles",
              f"touch /home/{AGENT_USER}/.evilrc", 1, sbx)

        # Credential paths.
        for d in (".aws", ".ssh", ".config"):
            check(f"cannot read {d}", f"ls /home/{AGENT_USER}/{d}", 1, sbx)
            check(f"cannot write {d}",
                  f"touch /home/{AGENT_USER}/{d}/probe", 1, sbx)

        # PATH and interpreter integrity. These are the controls E2B's
        # own configuration script removes and the harness puts back.
        check("cannot drop a binary on PATH",
              "printf 'x' > /usr/local/bin/zzprobe", 1, sbx)
        check("cannot overwrite the interpreter",
              "printf 'x' > /usr/local/bin/python3", 1, sbx)
        check("cannot plant an importable module",
              "python3 -c \"import site;p=site.getsitepackages()[0];"
              "open(p+'/evil.py','w').write('x')\"", 1, sbx)
        check("cannot write /code", "touch /code/probe", 1, sbx)
        ver = sbx.commands.run("python3 -V", timeout=30).stdout.strip()
        results.append((ver.startswith("Python 3"),
                        "interpreter is intact", ver))

        # Nothing credential shaped arrives through the environment.
        env = sbx.commands.run("env", timeout=30).stdout
        leaked = [ln.split("=")[0] for ln in env.splitlines()
                  if any(k in ln.upper().split("=")[0]
                         for k in ("KEY", "TOKEN", "SECRET", "PASSWORD", "CRED"))]
        results.append((not leaked, "no credential shaped env vars",
                        f"found={leaked or 'none'}"))
    finally:
        sbx.kill()

    width = max(len(n) for _, n, _ in results)
    for ok, name, detail in results:
        print(f"[{'PASS' if ok else 'FAIL'}] {name.ljust(width)}  {detail}")
    failed = [n for ok, n, _ in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} controls hold")
    if failed:
        print("FAILED: " + ", ".join(failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
