"""#1391 r6 L1-L3: every copy of a lab fact agrees with `lab-surface.json`, its one owner.

The edge's published ports and the cloud firewall's rules match the surface's ports; the services
the surface names exist in the lab compose and sit on `ingress`; the edge and the endpoint-query
service are never on `default` (Zeek, the role hosts) and never run `python app.py` (Shuffle's
reaper); `ingress` pins a non-`br-` bridge name; the process-list argv capture records, the
service runs and the replica shim answers is one; Falco excuses the service's socket mount.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

PLAYGROUND = Path(__file__).resolve().parents[2]
SURFACE = json.loads((PLAYGROUND / "lab-surface.json").read_text())
COMPOSE = yaml.safe_load((PLAYGROUND / "compose.yml").read_text())
SERVICES = COMPOSE["services"]


def _ports(spec: str) -> set[int]:
    """Host ports of a compose `ip:host:container` (ranges expanded)."""
    host = spec.rsplit(":", 2)[-2]
    lo, _, hi = host.partition("-")
    return set(range(int(lo), int(hi or lo) + 1))


def test_the_edge_publishes_exactly_the_surfaces_ports_on_the_public_address_only():
    edge = SERVICES["edge"]
    published = set().union(*(_ports(p) for p in edge["ports"]))
    assert published == {int(s["port"]) for s in SURFACE["systems"].values()}
    assert all(p.startswith("${V2_LAB_PUBLIC_ADDRESS") for p in edge["ports"]), edge["ports"]


def test_the_firewall_opens_exactly_the_surfaces_ports_to_the_ssh_sources():
    text = (PLAYGROUND / "infra" / "firewall.tf").read_text()
    rules = re.findall(r'rule \{(.*?)\n  \}', text, re.S)
    opened: set[int] = set()
    for rule in rules:
        port = re.search(r'port\s*=\s*"([^"]+)"', rule)
        if not port or port.group(1) == "22":
            continue
        assert "var.ssh_source_cidrs" in rule, rule
        lo, _, hi = port.group(1).partition("-")
        opened |= set(range(int(lo), int(hi or lo) + 1))
    assert opened == {int(s["port"]) for s in SURFACE["systems"].values()}


def test_every_service_the_surface_names_is_on_ingress_and_the_ingress_pair_never_reaches_default():
    for spec in SURFACE["systems"].values():
        nets = SERVICES[spec["service"]].get("networks", ["default"])
        assert "ingress" in nets, (spec["service"], nets)
    for name in ("edge", "endpoint-query"):
        assert SERVICES[name]["networks"] == ["ingress"], name
    bridge = COMPOSE["networks"]["ingress"]["driver_opts"]["com.docker.network.bridge.name"]
    assert not bridge.startswith("br-") and len(bridge) <= 15


def test_no_new_container_runs_the_command_shuffles_reaper_kills():
    for name in ("edge", "endpoint-query"):
        entry = [line for line in (PLAYGROUND / name / "Dockerfile").read_text().splitlines()
                 if line.startswith(("ENTRYPOINT", "CMD"))]
        command = " ".join(str(c) for c in SERVICES[name].get("command", []))
        assert entry and not any("app.py" in line for line in entry) and "app.py" not in command


def test_the_process_list_argv_has_one_owner():
    import importlib.util
    spec = importlib.util.spec_from_file_location("lab_ops_1391", PLAYGROUND / "scripts" / "lab_ops.py")
    lab_ops = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(lab_ops)
    argv = SURFACE["ps_argv"]
    assert lab_ops.PS_ARGV == argv
    shim = (PLAYGROUND / "hosts" / "base" / "ps-shim").read_text()
    assert f'if [ "$*" = "{" ".join(argv[1:])}" ]' in shim
    assert lab_ops.STUBS == {s["service"]: s["port"] for n, s in SURFACE["systems"].items()
                             if n not in ("host-state", "elastic")}
    assert lab_ops.HOST_STATE_PORT == SURFACE["systems"]["host-state"]["port"]
    assert lab_ops.ES_PORT == SURFACE["systems"]["elastic"]["port"]


def test_falco_excuses_the_endpoint_query_services_socket_mount():
    rules = yaml.safe_load((PLAYGROUND / "falco" / "falco_rules.local.yaml").read_text())
    excused = next(r for r in rules if r.get("list") == "soar_socket_mount_images")["items"]
    assert SERVICES["endpoint-query"]["image"].split(":")[0] in excused


def test_es_init_writes_the_defender_read_only_user_in_a_script_that_still_parses():
    """The whole one-shot is one single-quoted `bash -c` argument: an apostrophe in a comment
    splits it (and `compose config` refuses the file)."""
    import shlex
    import subprocess
    argv = shlex.split(SERVICES["es-init"]["command"])
    assert argv[:2] == ["bash", "-c"] and len(argv) == 3, argv[:3]
    script = argv[2].replace("$$", "$")
    assert "/_security/user/defender-readonly" in script and '\\"monitor\\"' in script
    assert subprocess.run(["bash", "-n", "-c", script]).returncode == 0
