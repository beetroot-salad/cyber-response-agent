"""`free_port` hands a port the caller can bind: never one from the kernel's ephemeral range, never a repeat, and one
xdist worker's ports are not another's (the bind-to-0 pick it replaced lost its port to other sockets before the
program bound it)."""
from __future__ import annotations

import socket

from defender.tests.support.api import _server1083 as server


def test_a_port_is_bindable_at_once_and_a_call_never_repeats_one_of_the_last_64():
    ports = [server.free_port() for _ in range(64)]
    assert len(set(ports)) == len(ports)
    for port in ports[:20]:
        with socket.socket() as s:
            s.bind(("127.0.0.1", port))


def test_a_port_is_below_the_kernels_ephemeral_range_where_that_leaves_room():
    floor = server._ephemeral_floor()
    if floor - server._PORT_FLOOR < server._SLOTS * 8:
        return  # the system's range leaves no room: the bind-to-0 fallback
    assert all(server._PORT_FLOOR <= server.free_port() < floor for _ in range(50))


def test_two_workers_draw_from_disjoint_slices(monkeypatch):
    drawn: dict[str, set[int]] = {}
    for worker in ("gw0", "gw1", "gw2", "gw3"):
        monkeypatch.setenv("PYTEST_XDIST_WORKER", worker)
        server._RECENT.clear()
        drawn[worker] = {server.free_port() for _ in range(100)}
    names = list(drawn)
    for i, a in enumerate(names):
        for b in names[i + 1:]:
            assert not drawn[a] & drawn[b], (a, b)


def test_a_port_is_never_one_a_browser_refuses(monkeypatch):
    """Chromium fails a navigation to a restricted port (10080 among them) with ERR_UNSAFE_PORT: the draw skips them."""
    monkeypatch.setenv("PYTEST_XDIST_WORKER", "gw0")
    server._RECENT.clear()
    if server._ephemeral_floor() - server._PORT_FLOOR < server._SLOTS * 8:
        return
    assert server._slice_port(lambda _width: 10080 - server._PORT_FLOOR) is None  # a draw that only finds 10080
    assert server._UNSAFE_PORTS.isdisjoint({server.free_port() for _ in range(40)})
