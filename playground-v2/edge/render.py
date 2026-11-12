"""Render the lab edge's nginx config from `lab-surface.json` (#1391 r6 L1, L3).

The edge is nginx; this file owns only the rules. Per HTTP port it admits GET on any path outside
`/admin`, plus that port's declared writes (HEAD is not admitted: no service behind the edge
answers it and no product adapter sends it), and refuses everything else with 404 whatever
the key. With the key check on (live) a request must also carry `Authorization: Bearer <key>`
(401 otherwise); the header is never forwarded. The key is lowercase hex (the entrypoint refuses
any other): nginx compares map keys ignoring case, which then loses nothing. The frozen engine's frontend is the same config
with the key check off: it is reached only through the operator's SSH forward. A `passthrough`
port (Elasticsearch) is a TCP stream: the upstream authenticates the caller itself.

nginx matches locations against the decoded, normalized path but forwards the raw one. So a raw
path that normalizing would change is refused first (`//`, an encoded `/` `\\` `.` or NUL, a
`\\`, a `.`/`..` segment, a target not starting with `/`): every admitted request's raw path then
means exactly what its rules judged.

    python render.py <surface.json> <out-dir>   # writes nginx-keyed.conf.template, nginx-open.conf
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

KEY_PLACEHOLDER = "${V2_LAB_API_KEY}"
#: Docker's embedded DNS: names resolve per request, so a restarted service's new address is found.
RESOLVER = "127.0.0.11"
UPSTREAM_TIMEOUT = "60s"
#: A raw path normalizing would change, or a target that is not origin-form.
BAD_RAW_PATH = r'"~^(?:[^/]|[^?]*(?://|%2[fF]|%5[cC]|%2[eE]|%00|\x5c|/\.\.?(?:/|\?|$)))"'


def _write_location(pattern: str) -> str:
    """A declared write path (`*` = one non-empty segment) as an anchored nginx regex."""
    parts = []
    for seg in pattern.strip("/").split("/"):
        if seg == "*":
            parts.append("[^/]+")
        elif re.fullmatch(r"[A-Za-z0-9_.~-]+", seg):
            parts.append(re.escape(seg))
        else:
            raise ValueError(f"unsupported write path segment {seg!r} in {pattern!r}")
    return "^/" + "/".join(parts) + "/?$"


def _http_server(name: str, spec: dict, service_port: int, key_check: bool) -> str:
    port = int(spec["port"])
    lines = [f"    server {{  # {name}",
             f"        listen {port};",
             f"        set $edge_upstream {spec['service']}:{service_port};"]
    if key_check:
        lines.append('        if ($edge_key_ok = 0) { return 401 \'{"detail":"a bearer key is required"}\'; }')
    lines += ['        if ($edge_bad_path) { return 404 \'{"detail":"not served"}\'; }',
              '        location = /admin { return 404 \'{"detail":"not served"}\'; }',
              '        location ^~ /admin/ { return 404 \'{"detail":"not served"}\'; }']
    writes: dict[str, set[str]] = {}
    for method, pattern in spec.get("writes", []):
        writes.setdefault(_write_location(pattern), set()).add(method)
    for regex, methods in writes.items():
        allowed = "|".join(sorted({"GET", *methods}))
        lines += [f"        location ~ {regex} {{",
                  f"            if ($request_method !~ ^({allowed})$) {{ return 404 '{{\"detail\":\"not served\"}}'; }}",
                  "            proxy_pass http://$edge_upstream;",
                  "        }"]
    lines += ["        location / {",
              "            if ($request_method != GET) { return 404 '{\"detail\":\"not served\"}'; }",
              "            proxy_pass http://$edge_upstream;",
              "        }",
              "    }"]
    return "\n".join(lines)


def render(surface: dict, *, key_check: bool) -> str:
    service_port = int(surface["service_port"])
    http, stream = [], []
    for name, spec in surface["systems"].items():
        if spec.get("passthrough"):
            port = int(spec["port"])
            stream.append(f"    server {{  # {name}\n        listen {port};\n"
                          f"        set $edge_upstream {spec['service']}:{port};\n"
                          f"        proxy_pass $edge_upstream;\n    }}")
        else:
            http.append(_http_server(name, spec, service_port, key_check))
    key_map = ""
    if key_check:
        key_map = ("    map $http_authorization $edge_key_ok {\n        default 0;\n"
                   f'        "Bearer {KEY_PLACEHOLDER}" 1;\n    }}\n')
    return f"""# Rendered by edge/render.py from lab-surface.json ({'key check on' if key_check else 'key check off'}).
worker_processes 1;
error_log /dev/stderr warn;
pid /tmp/nginx.pid;
events {{ worker_connections 256; }}

http {{
    access_log /dev/stdout;
    server_tokens off;
    default_type application/json;
    client_max_body_size 1m;
    map_hash_bucket_size 256;   # the key's map entry (`Bearer ` + up to 128 hex) must fit one bucket
    resolver {RESOLVER} valid=10s ipv6=off;
    proxy_http_version 1.1;
    proxy_set_header Connection "";
    proxy_set_header Authorization "";
    proxy_connect_timeout 5s;
    proxy_read_timeout {UPSTREAM_TIMEOUT};
    proxy_send_timeout {UPSTREAM_TIMEOUT};
    proxy_intercept_errors off;
{key_map}    map $request_uri $edge_bad_path {{
        default 0;
        {BAD_RAW_PATH} 1;
    }}

{chr(10).join(http)}
}}

stream {{
    resolver {RESOLVER} valid=10s ipv6=off;
    proxy_connect_timeout 5s;
{chr(10).join(stream)}
}}
"""


def main(argv: list[str]) -> int:
    surface = json.loads(Path(argv[1]).read_text())
    out = Path(argv[2])
    out.mkdir(parents=True, exist_ok=True)
    (out / "nginx-keyed.conf.template").write_text(render(surface, key_check=True))
    (out / "nginx-open.conf").write_text(render(surface, key_check=False))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
