"""
company-agent-python-hardened

E2B template definition. This is the Ring 3 boundary for the harness in
agent_sandbox.py. Everything the article attributes to "the template"
is enforced here, at the OS level, before any agent code runs.

Verified against E2B's live API: verify_ring3.py reports 21 of 21
controls holding inside a sandbox opened from this template. E2B's
default user was confirmed to hold passwordless sudo, which is the
reason the agent account below exists.

One control this template cannot enforce on its own. E2B runs its own
configuration script AFTER these layers, and that script makes /usr/local
and /code world writable. /usr/local/bin is first on PATH and holds the
Python interpreter and site-packages, so on an unrepaired sandbox the
agent can shadow binaries, overwrite the interpreter, and plant importable
modules. Verified by doing it: python3 -V returned PWNED. The harness
closes this at session start through HARDEN_CMD in agent_sandbox.py,
before any agent code runs, and refuses the session if it does not take.

A note on symlinks. The agent can create a symlink in /workspace pointing
anywhere. What decides the outcome is the target's own ownership and mode,
not the link. A link to a credential path or to /etc/shadow is refused. A
link to a world readable file reads, which is the OS behaving correctly,
and is why a clean microVM carries nothing sensitive that is world
readable and why secrets arrive through the broker rather than the disk.

Why an explicit agent account exists
------------------------------------
E2B's default sandbox user is `user`, and `user` holds passwordless
sudo. Ownership and mode would be decorative under that account, since
any command could elevate past them. So this template creates a separate
`agent` account that is in no privileged group and is denied in sudoers,
sets it as the template default with set_user(), and gives it exactly one
writable location.

What the agent can do
---------------------
  /workspace              read, write   the only writable location
  /srv/reference          read only     docs and source the agent consults
  /home/agent             read only     cannot plant or edit dotfiles
  everything else         per OS perms, with no path to root

Why /home/agent is not writable
-------------------------------
E2B runs every command through `bash -l -c`, which sources login files.
A writable ~/.bashrc is a persistence vector: the agent writes it once
and every later command in the session executes that code. Root owns the
home directory and its dotfiles, so the agent reads them and nothing more.
This is the "no writes to agent config files" control of Ring 3.

Why reference material sits outside /workspace
----------------------------------------------
The agent owns /workspace, so it can unlink anything inside it including
a directory it is not supposed to modify. Read only reference material
has to live on a path the agent does not own. DOCS_ROOT in
agent_sandbox.py points at /srv/reference/docs for that reason.

Build:
    E2B_API_KEY=... python template.py

License: MIT
"""
import os

from e2b import Template

AGENT_USER = "agent"
WORKSPACE = "/workspace"
REFERENCE = "/srv/reference"
TEMPLATE_NAME = "company-agent-python-hardened"

template = (
    Template()
    .from_python_image("3.12")

    # Unprivileged runtime account. No sudo group, no wheel, no shell
    # escalation path. The account exists only to run agent code.
    .run_cmd(
        f"useradd --create-home --shell /bin/bash {AGENT_USER}",
        user="root",
    )
    # Belt and braces. Even if a base image ships a blanket sudoers rule,
    # this drop-in denies the agent account by name. /etc/sudoers.d does
    # not exist on images that never installed sudo, so it is created
    # first. The drop-in then holds whether or not sudo arrives later.
    .run_cmd(
        f"mkdir -p /etc/sudoers.d "
        f"&& printf '{AGENT_USER} ALL=(ALL) !ALL\\n' > /etc/sudoers.d/99-deny-agent "
        f"&& chmod 0440 /etc/sudoers.d/99-deny-agent",
        user="root",
    )

    # The single writable location.
    .run_cmd(
        f"mkdir -p {WORKSPACE} "
        f"&& chown {AGENT_USER}:{AGENT_USER} {WORKSPACE} "
        f"&& chmod 0700 {WORKSPACE}",
        user="root",
    )

    # Read only reference material, outside the writable workspace so the
    # agent cannot unlink or replace it.
    .run_cmd(
        f"mkdir -p {REFERENCE}/docs {REFERENCE}/src",
        user="root",
    )
    # Ship the actual material into the image. Root owns it and mode 0555
    # makes it readable and not writable. Point this at whatever the agent
    # is allowed to consult.
    .copy("reference/docs", f"{REFERENCE}/docs", user="root", mode=0o555)
    .run_cmd(
        f"chown -R root:root {REFERENCE} && chmod -R 0555 {REFERENCE}",
        user="root",
    )

    # Home directory is readable and not writable. Root owns the dotfiles
    # bash sources on every command, so the agent cannot establish
    # persistence through them, and cannot create new ones either.
    .run_cmd(
        f"chown root:root /home/{AGENT_USER} "
        f"&& chmod 0755 /home/{AGENT_USER} "
        f"&& for f in .bashrc .bash_profile .profile; do "
        f"  touch /home/{AGENT_USER}/$f; "
        f"  chown root:root /home/{AGENT_USER}/$f; "
        f"  chmod 0644 /home/{AGENT_USER}/$f; "
        f"done",
        user="root",
    )

    # Credential paths exist as root owned and unreadable, so nothing can
    # plant them later and nothing can read them if something does. A fresh
    # microVM carries no developer credentials to begin with. These are
    # placeholders that stay empty, not blocks on files that are there.
    .run_cmd(
        f"for d in .aws .ssh .config .kube .docker .npm .gnupg; do "
        f"  mkdir -p /home/{AGENT_USER}/$d; "
        f"  chown root:root /home/{AGENT_USER}/$d; "
        f"  chmod 0000 /home/{AGENT_USER}/$d; "
        f"done",
        user="root",
    )

    # No build time secrets reach the running sandbox. Secrets arrive
    # through the broker at call time, never through the environment.
    .set_envs({"PYTHONDONTWRITEBYTECODE": "1", "HOME": f"/home/{AGENT_USER}"})

    # set_user last so it is the account the sandbox defaults to. The
    # harness never passes user= to commands.run, so every dispatched
    # command lands here. A harness that passed user="root" would step
    # around this template entirely.
    .set_workdir(WORKSPACE)
    .set_user(AGENT_USER)
)


if __name__ == "__main__":
    key = os.environ.get("E2B_API_KEY")
    if not key:
        raise SystemExit("set E2B_API_KEY to build")
    # Template.build is a staticmethod and takes the template as its
    # first argument. api_key flows through ApiParams.
    built = Template.build(
        template,
        alias=TEMPLATE_NAME,
        api_key=key,
        on_build_logs=lambda e: print(e),
    )
    print(f"built {TEMPLATE_NAME}: {built}")
