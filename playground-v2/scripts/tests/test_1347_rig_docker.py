"""#1347 r6.4.3 review repair: the rig docker's own shell, checked against what sh does.

These test the FAKE (`_rig_docker.RigDocker`), not the lab: a lock store or a lab step is judged by the rig, so a
shell form the rig gets wrong would pass or fail lab code for the wrong reason. Each case is a form a lab
implementation may use; a form the rig does not model must land in `unmodelled` (the rigs fail on it), never
answer as if it ran.
"""
from __future__ import annotations

import pytest
from _lab_fakes import T, FakeClock, Journal, instant
from _rig_docker import RigDocker


def _rig():
    journal = Journal()
    docker = RigDocker(journal=journal, clock=FakeClock(journal, instant(T)))
    box = docker.existing("deploy", "box", "alpine")
    return docker, box


def _sh(docker, script, *args, stdin=b""):
    done = docker(["docker", "exec", "-i", "box", "sh", "-c", script, "sh", *args], input=stdin, capture_output=True)
    return done.returncode, done.stdout


def test_a_variable_assigned_from_a_substitution_is_put_in_where_it_is_used():
    docker, box = _rig()
    docker.stores.setdefault(docker.resolve(box, "/r")[0], {})[docker.resolve(box, "/r")[1]] = b"abc"
    rc, out = _sh(docker, 't=$(cat "$1"); printf "%s-%s" "$t" "$2"', "/r", "x")
    assert (rc, out, docker.unmodelled) == (0, b"abc-x", [])


def test_a_substitution_whose_command_is_not_modelled_stays_unmodelled():
    docker, _box = _rig()
    rc, _out = _sh(docker, 't=$(sort -u "$1"); printf "%s" "$t"', "/r")
    assert rc == 0 and docker.unmodelled, "the unmodelled command inside $(...) was dropped"


@pytest.mark.parametrize("script", ['grep -q "a.*b" "$1"', "grep -q '^x' \"$1\"", 'grep -qE "a|b" "$1"'])
def test_a_regex_grep_is_not_modelled(script):
    docker, _box = _rig()
    _sh(docker, script, "/r")
    assert docker.unmodelled


def test_a_fixed_grep_matches_literally():
    docker, box = _rig()
    store, key, _ro = docker.resolve(box, "/r")
    docker.stores.setdefault(store, {})[key] = b'{"token": "a.b"}'
    assert _sh(docker, 'grep -qF "\\"token\\": \\"$2\\"" "$1"', "/r", "a.b")[0] == 0
    assert _sh(docker, 'grep -qF "\\"token\\": \\"$2\\"" "$1"', "/r", "axb")[0] == 1
    assert docker.unmodelled == []


@pytest.mark.parametrize("script", ['exec 9>>"$1.lock"; flock -x 9 || exit 4; printf ok', 'flock "$1.lock" printf ok'])
def test_the_elasticsearch_image_has_no_flock_and_other_images_do(script):
    """#1347 live check 16: the live Elasticsearch image (RHEL 9 minimal) has no `flock`: `sh -c` answers
    `sh: line 1: flock: command not found`, exit 127, and runs nothing under it; an image that has it (the
    alpine/busybox resolver here) runs the command under the lock. A failure the image really gives, modelled:
    not a gap."""
    journal = Journal()
    docker = RigDocker(journal=journal, clock=FakeClock(journal, instant(T)))
    docker.existing("deploy", "es", "docker.elastic.co/elasticsearch/elasticsearch:9.3.3")
    docker.existing("deploy", "resolver", "soc-playground/unbound:local")

    def run(name):
        done = docker(["docker", "exec", name, "sh", "-c", script, "sh", "/r"], capture_output=True, text=True)
        return done.returncode, done.stdout, done.stderr

    rc, out, err = run("es")
    assert rc in (4, 127) and out == "", (rc, out, err)
    assert "sh: line 1: flock: command not found" in err, err
    assert run("resolver") == (0, "ok", "")
    assert docker.unmodelled == []


def test_a_shared_flock_is_not_modelled():
    docker, _box = _rig()
    _sh(docker, 'flock -s "$1.lock" true', "/r")
    assert docker.unmodelled


@pytest.mark.parametrize("script", [
    '( flock -x 9; printf "%s" "$2" > "$1" ) 9>"$1.lock"',
    '{ flock -x 9; printf "%s" "$2" > "$1"; } 9>"$1.lock"',
    'exec 9<>"$1.lock"; flock -x 9; printf "%s" "$2" > "$1"',
    ': > "$1.lock"; exec 9<"$1.lock"; flock -x 9; printf "%s" "$2" > "$1"'])
def test_a_lock_fd_opened_on_a_group_or_by_exec_is_modelled(script):
    docker, box = _rig()
    rc, _out = _sh(docker, script, "/r", "v")
    assert (rc, docker.unmodelled, docker.read_file(box, "/r")) == (0, [], b"v")
    assert docker.read_file(box, "/r.lock") is not None


def test_exit_in_a_subshell_ends_only_the_subshell():
    docker, _box = _rig()
    rc, out = _sh(docker, '( printf a; exit 3; printf b ) && printf c || printf d')
    assert (rc, out, docker.unmodelled) == (0, b"ad", [])


def test_flock_u_releases_the_lock_it_names():
    """`flock -u N` drops the lock on fd N: a later delete is no longer under it (the armed operator acts)."""
    docker, box = _rig()
    rc, _ = _sh(docker, 'exec 9>>"$1.lock"; flock -x 9; set -C; printf "%s" mine > "$1"', "/r")
    assert rc == 0
    other = []
    docker.race_record(box, "/r", lambda: other.append(docker.read_file(box, "/r")))
    _sh(docker, 'exec 9>>"$1.lock"; flock -x 9; flock -u 9; rm -f "$1"', "/r")
    assert other == [b"mine"], "the release after `flock -u` was treated as still holding the lock"


def test_a_read_outside_the_lock_lets_the_other_operator_act_before_the_lock_is_taken():
    docker, box = _rig()
    _sh(docker, 'exec 9>>"$1.lock"; flock -x 9; set -C; printf "%s" mine > "$1"', "/r")
    seen = []
    docker.race_record(box, "/r", lambda: seen.append("raced"))
    _sh(docker, 'grep -qF mine "$1" || exit 3; flock "$1.lock" rm -f "$1"', "/r")
    assert seen == ["raced"]


def test_a_file_an_image_holds_is_read_in_a_container_of_that_image():
    docker, box = _rig()
    docker.image_files["alpine"] = {"/opt/shim.so": b"\x7fELF"}
    assert docker.read_file(box, "/opt/shim.so") == b"\x7fELF"
    other = docker.existing("deploy", "other", "busybox")
    assert docker.read_file(other, "/opt/shim.so") is None


@pytest.mark.parametrize("flag", ["-d", "--data-binary", "-XPOST"])
def test_a_curl_post_to_a_stub_is_not_read_as_a_stub_read(flag):
    assert RigDocker._stub_request(["curl", "-s", flag, "@-", "http://localhost:8080/admin/overlay/"]) is None
    assert RigDocker._stub_request(["curl", "-s", "http://localhost:8080/hosts/h1"]) is not None


def _host_rig():
    """A role host with a live agent volume, on the lab server (live check, 2026-11-10)."""
    journal = Journal()
    docker = RigDocker(journal=journal, clock=FakeClock(journal, instant(T)))
    docker.volume("lab", "web-1-agent").update({"data/elastic-agent-9.3.3-d70142/state.enc": b"state"})
    host = docker.existing("lab", "web-1", "soc-playground-web-1",
                           mounts=[("/var/lib/elastic-agent", "store", docker.volumes[("lab", "web-1-agent")], False)])
    host.extra["role_host"] = True
    return docker, host


def _docker(docker, *args, **kw):
    return docker(["docker", "--context", "lab", *args], capture_output=True, **kw)


def test_pause_and_unpause_report_the_states_docker_reports_and_refuse_as_docker_does():
    docker, host = _host_rig()
    status = lambda: _docker(docker, "inspect", "-f", "{{.State.Status}}", "web-1", text=True).stdout.strip()
    assert _docker(docker, "pause", "web-1").returncode == 0 and status() == "paused"
    assert _docker(docker, "inspect", "-f", "{{.State.Running}}", "web-1", text=True).stdout.strip() == "true"
    assert _docker(docker, "inspect", "-f", "{{.State.Paused}}", "web-1", text=True).stdout.strip() == "true"
    assert _docker(docker, "pause", "web-1").returncode == 1, "a paused container paused again"
    done = _docker(docker, "exec", "web-1", "sh", "-c", "true", text=True)
    assert done.returncode == 1 and "is paused" in done.stderr, done
    assert _docker(docker, "start", "web-1").returncode == 1
    assert _docker(docker, "unpause", "web-1").returncode == 0 and status() == "running"
    assert _docker(docker, "unpause", "web-1").returncode == 1, "a running container unpaused"
    assert _docker(docker, "exec", "web-1", "sh", "-c", "true").returncode == 0
    missing = _docker(docker, "pause", "web-9", text=True)
    assert missing.returncode == 1 and "No such container" in missing.stderr
    assert _docker(docker, "unpause", "web-9").returncode == 1
    _docker(docker, "stop", "web-1")
    assert _docker(docker, "pause", "web-1").returncode == 1, "a stopped container paused"
    assert docker.unmodelled == []


def test_a_tar_of_a_running_hosts_volume_sees_it_change_and_a_paused_one_does_not():
    """Live check (2026-11-10): `run --volumes-from <host>:ro --entrypoint tar ... -cf - .` over a running host's
    agent volume exits 1 (`file changed as we read it`, the archive still printed); with the host paused it
    exits 0 with the same members."""
    docker, host = _host_rig()
    argv = ["run", "--rm", "--volumes-from", "web-1:ro", "--entrypoint", "tar", "--network", "none",
            "soc-playground-web-1", "-C", "/var/lib/elastic-agent", "-cf", "-", "."]
    live = _docker(docker, *argv)
    assert live.returncode == 1, live
    assert b"tar: ./data/elastic-agent-9.3.3-d70142/state.enc: file changed as we read it" in live.stderr

    _docker(docker, "pause", "web-1")
    frozen = _docker(docker, *argv)
    _docker(docker, "unpause", "web-1")
    assert (frozen.returncode, frozen.stderr) == (0, b""), frozen
    assert frozen.stdout == live.stdout
    assert docker.unmodelled == []
