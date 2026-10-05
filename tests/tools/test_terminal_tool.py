"""Regression tests for sudo detection, sudo password handling, and the
foreground retry loop's environment re-resolution."""

import json
import time as _real_time
from types import SimpleNamespace

import tools.terminal_tool as terminal_tool
import tools.terminal_tool_sudo as terminal_tool_sudo


def setup_function():
    terminal_tool_sudo._reset_cached_sudo_passwords()


def teardown_function():
    terminal_tool_sudo._reset_cached_sudo_passwords()


def test_searching_for_sudo_does_not_trigger_rewrite(monkeypatch):
    monkeypatch.delenv("SUDO_PASSWORD", raising=False)
    monkeypatch.delenv("HERMES_INTERACTIVE", raising=False)

    command = "rg --line-number --no-heading --with-filename 'sudo' . | head -n 20"
    transformed, sudo_stdin = terminal_tool_sudo._transform_sudo_command(command)

    assert transformed == command
    assert sudo_stdin is None








def test_actual_sudo_command_uses_configured_password(monkeypatch):
    monkeypatch.setenv("SUDO_PASSWORD", "testpass")
    monkeypatch.delenv("HERMES_INTERACTIVE", raising=False)

    transformed, sudo_stdin = terminal_tool_sudo._transform_sudo_command("sudo apt install -y ripgrep")

    assert transformed == "sudo -S -p '' apt install -y ripgrep"
    assert sudo_stdin == "testpass\n"


def test_explicit_empty_sudo_password_tries_empty_without_prompt(monkeypatch):
    monkeypatch.setenv("SUDO_PASSWORD", "")
    monkeypatch.setenv("HERMES_INTERACTIVE", "1")

    def _fail_prompt(*_args, **_kwargs):
        raise AssertionError("interactive sudo prompt should not run for explicit empty password")

    monkeypatch.setattr(terminal_tool_sudo, "_prompt_for_sudo_password", _fail_prompt)

    transformed, sudo_stdin = terminal_tool_sudo._transform_sudo_command("sudo true")

    assert transformed == "sudo -S -p '' true"
    assert sudo_stdin == "\n"


def test_headless_sudo_never_runs_backend_nopasswd_probe(monkeypatch):
    """No prompt can fire without a UI, so the backend round trip must not be paid."""
    monkeypatch.delenv("SUDO_PASSWORD", raising=False)
    monkeypatch.delenv("HERMES_INTERACTIVE", raising=False)
    terminal_tool.set_sudo_password_callback(None)

    def _fail_probe():
        raise AssertionError("headless sudo must not probe the backend")

    assert terminal_tool_sudo._transform_sudo_command("sudo true", sudo_nopasswd_check=_fail_probe) == (
        "sudo true", None)


def test_validate_workdir_blocks_shell_metacharacters_in_windows_paths():
    assert terminal_tool._validate_workdir(r"C:\Users\Alice\project; rm -rf /")
    assert terminal_tool._validate_workdir(r"C:\Users\Alice\project$(whoami)")
    assert terminal_tool._validate_workdir("C:\\Users\\Alice\\project\nwhoami")


def test_validate_workdir_allows_unicode_filesystem_paths():
    assert terminal_tool._validate_workdir(
        "/Users/alice/Documents/Obs_Hermes_Data/项目-projects/客户拜访"
    ) is None
    assert terminal_tool._validate_workdir("/tmp/テスト") is None
    assert terminal_tool._validate_workdir("/home/jürgen/über projekt") is None


def test_validate_workdir_still_blocks_metachars_in_unicode_paths():
    # Widening to Unicode letters must not open the injection boundary:
    # shell metacharacters and control chars stay rejected even when mixed
    # with non-ASCII path segments.
    assert terminal_tool._validate_workdir("/tmp/テスト; rm -rf /")
    assert terminal_tool._validate_workdir("/tmp/项目$(whoami)")
    assert terminal_tool._validate_workdir("/tmp/über`id`")
    assert terminal_tool._validate_workdir("/tmp/テスト\nwhoami")
    assert terminal_tool._validate_workdir("/tmp/项目|cat /etc/passwd")
    assert terminal_tool._validate_workdir("/tmp/ü\x00ber")


def test_literal_sudo_executables_receive_password_stdin(monkeypatch):
    monkeypatch.setenv("SUDO_PASSWORD", "testpass")
    for prefix in ("", "VAR='a b' ", "env ", "'/usr/bin/env' -i -u UNUSED X=1 ",
                   "env --unset=UNUSED --chdir /tmp -- X=1 ", "env -uUNUSED -C/tmp "):
        for executable in ("sudo", "/usr/bin/sudo", "'/opt/my tools/sudo'", '"/usr/bin/sudo"'):
            command = prefix + executable + " -u root true"
            rewritten, stdin = terminal_tool_sudo._transform_sudo_command(command)
            assert rewritten == prefix + executable + " -S -p '' -u root true"
            assert stdin == "testpass\n"


def test_sudo_rewrite_preserves_env_operands_and_prose(monkeypatch):
    monkeypatch.setenv("SUDO_PASSWORD", "testpass")
    commands = (
        "echo '/usr/bin/sudo true'", "env echo sudo true", "env -u sudo echo ok",
        "env --chdir sudo echo ok", "env --unset=sudo echo ok", "env -- sudo=1 echo ok",
        ">/tmp/sudo echo ok", "env 2>/tmp/sudo echo ok", "env > /tmp/sudo echo ok",
        "/tmp/{a,b}/sudo true", "env X=1 -u UNUSED sudo", "env - -u UNUSED sudo", "env echo /usr/bin/sudo", "/tmp/*/sudo true",
        "env -S 'sudo true'", "env --unknown sudo true", "env --help sudo",
        "bash -c 'sudo true'", "echo ok # prose; /usr/bin/sudo true",
        '"/usr/bin/sudo', "env -u sudo", "env X=sudo", '"X=1" /usr/bin/sudo true',
    )
    for command in commands:
        assert terminal_tool_sudo._transform_sudo_command(command) == (command, None)


def test_count_real_sudo_invocations_ignores_mentions(monkeypatch):
    assert terminal_tool_sudo._count_real_sudo_invocations("grep sudo README.md") == 0
    assert terminal_tool_sudo._count_real_sudo_invocations("sudo a; sudo b") == 2


# --- foreground retry: environment re-resolution ---

class _FakeEnv:
    """Minimal environment: records execute() calls, optional fixed failure."""

    host_cwd = None
    cwd = "/workspace"

    def __init__(self, container_id, fail_with=None, fail_times=None):
        self._container_id = container_id
        self._fail_with = fail_with
        # None -> fail forever; int -> fail the first N calls, then succeed
        self._fail_times = fail_times
        self.execute_calls = 0

    def execute(self, command, **kwargs):
        self.execute_calls += 1
        if self._fail_with is not None and (
            self._fail_times is None or self.execute_calls <= self._fail_times
        ):
            raise self._fail_with
        return {"output": "ok", "returncode": 0}


class _RecordingTime:
    """``time`` stand-in whose sleep() is instant and recorded."""

    sleeps: list = []

    def __getattr__(self, name):
        return getattr(_real_time, name)

    def sleep(self, seconds):
        type(self).sleeps.append(seconds)


def _retry_plan():
    return SimpleNamespace(
        env_type="docker", effective_task_id="profile:x", effective_timeout=5,
        cwd="/workspace", host_cwd=None,
    )


def _run_retry_call(env, monkeypatch, *, session_key, registry=None):
    monkeypatch.setattr(terminal_tool, "_active_environments", dict(registry or {}))
    monkeypatch.setattr(
        terminal_tool, "_last_activity",
        {key: _real_time.time() for key in (registry or {})},
    )
    _RecordingTime.sleeps = []
    monkeypatch.setattr(terminal_tool, "time", _RecordingTime())
    return terminal_tool._run_foreground(
        "true", env, _retry_plan(), task_id=None, session_id=None,
        session_key=session_key, workdir=None, approval_note=None,
        clear_interrupt=False, metered=False,
    )


def test_retry_reacquires_environment_after_idle_reaper_tore_it_down(monkeypatch):
    """Regression: the idle reaper can tear down the resolved handle between
    attempts; every retry against it then fails identically (docker:
    ``AssertionError: Container not started``) and the whole retry budget is
    wasted. The next attempt must run on a re-acquired, live environment."""
    dead = _FakeEnv(container_id=None, fail_with=AssertionError("Container not started"))
    live = _FakeEnv(container_id="abc123")
    acquired = []

    def _acquire(plan, task_id):
        acquired.append(task_id)
        return live

    monkeypatch.setattr(terminal_tool, "_acquire_env", _acquire)

    result = json.loads(_run_retry_call(dead, monkeypatch, session_key="retry-reacquire"))

    assert result["error"] is None, result
    assert result["exit_code"] == 0, result
    assert acquired, "the retry must re-acquire an environment after the handle was reaped"
    assert dead.execute_calls == 1
    assert live.execute_calls == 1
    # backoff pacing is unchanged: the successful attempt came after one wait
    assert _RecordingTime.sleeps == [2]


def test_retry_keeps_a_live_registered_environment(monkeypatch):
    """A still-registered, intact handle must be reused as-is — re-resolution
    must never churn a healthy backend (a shared container would be rebuilt
    under the other sessions using it)."""
    env = _FakeEnv(container_id="abc123", fail_with=RuntimeError("connection reset"), fail_times=1)

    def _no_acquire(plan, task_id):
        raise AssertionError("a healthy registered environment must not be re-acquired")

    monkeypatch.setattr(terminal_tool, "_acquire_env", _no_acquire)

    result = json.loads(_run_retry_call(
        env, monkeypatch, session_key="retry-keep", registry={"profile:x": env},
    ))

    assert result["error"] is None, result
    assert result["exit_code"] == 0, result
    assert env.execute_calls == 2
    assert _RecordingTime.sleeps == [2]
