"""Judge a run-all output file against what the design expects; exit 1 naming every probe that disagrees.

Usage: python3 verdict.py out/run-all-<date>.txt
"""

import re
import sys

NET_TARGETS = [
    "proxy-pod", "proxy-service", "worker-pod", "peer-job-pod",
    "node-gw-kubelet", "node-gw-apiserver", "node-gw-nodeport",
    "node-ip-kubelet", "node-ip-apiserver", "node-ip-nodeport",
    "apiserver-service", "kube-dns-tcp", "coredns-pod-tcp", "metadata", "outside", "dns-udp-resolve",
]
# Cloud metadata does not exist on a dev host or a CI runner, so its refusal has no control.
NO_CONTROL = {"metadata"}
LAUNCHER_ALLOWED = {"create secret", "delete secret", "exec into box t-box", "exec into job t-job", "list pods in jobs"}
CASES = 42  # two base templates and 40 changes (gen-admission.py)


def sections(text):
    out, name = {}, None
    for line in text.splitlines():
        if line.startswith("## "):
            name = line[3:].strip()
            out[name] = []
        elif name is not None:
            out[name].append(line)
    return out


def find(secs, prefix):
    hits = [k for k in secs if k.startswith(prefix)]
    if len(hits) != 1:
        raise KeyError(f"section {prefix!r}: found {hits}")
    return secs[hits[0]]


def net(lines):
    got = {}
    for line in lines:
        m = re.match(r"(OPEN|CLOSED)\s+(\S+)", line)
        if m:
            got[m.group(2)] = m.group(1)
    return got


def main(path):
    secs = sections(open(path, encoding="utf-8").read())
    fails = []

    def check(name, ok, detail=""):
        print(("PASS " if ok else "FAIL ") + name + (f": {detail}" if detail and not ok else ""))
        if not ok:
            fails.append(name)

    p1 = "\n".join(find(secs, "probe 1:"))
    box = p1.split("-- p-box", 1)[1].split("-- p-runc", 1)[0]
    job = p1.split("-- p-job", 1)[1].split("-- p-box", 1)[0]
    check("1 box has loopback only", "eth0" not in box and "lo:" in box and "default via" not in box, box.strip())
    check("1 job pod has a network", "eth0" in job and "default via" in job, job.strip())
    check("1 both run under gVisor", box.count("Starting gVisor") == 1 and job.count("Starting gVisor") == 1)

    ctrl = net(find(secs, "probe 2a:"))
    want_ctrl = {t: ("CLOSED" if t in NO_CONTROL else "OPEN") for t in NET_TARGETS}
    check("2a every target reachable with no policy (controls)", ctrl == want_ctrl, str(ctrl))
    pol = net(find(secs, "probe 2b:"))
    want_pol = {t: ("OPEN" if t in ("proxy-pod", "proxy-service") else "CLOSED") for t in NET_TARGETS}
    check("2b job under policy reaches the proxy only", pol == want_pol, str(pol))
    for sec, label in (("probe 2c:", "2c runc pod under deny-all reaches nothing"),
                       ("probe 2d:", "2d box reaches nothing")):
        got = net(find(secs, sec))
        check(label, got == {t: "CLOSED" for t in NET_TARGETS}, str(got))
    p2e = "\n".join(find(secs, "probe 2e:"))
    check("2e worker accepts the proxy only",
          "proxy->worker: OPEN" in p2e and "other control pod->worker: CLOSED" in p2e, p2e)

    vol = find(secs, "probe 3:")
    passes = [x for x in vol if x.startswith("PASS ")]
    bad = [x for x in vol if x.startswith("FAIL ")]
    check("3 shared volume: 11 of 11", len(passes) == 11 and not bad, "; ".join(bad))

    for sec, alone in (("probe 4: admission (PSA restricted on", False), ("probe 4: admission (PSA off", True)):
        rows = [x for x in find(secs, sec) if re.match(r"(ADMITTED|REFUSED) ", x)]
        admitted = [x for x in rows if x.startswith("ADMITTED")]
        refused = [x for x in rows if x.startswith("REFUSED")]
        tag = "policy alone" if alone else "policy + Pod Security"
        check(f"4 {tag}: {CASES} cases", len(rows) == CASES, str(len(rows)))
        check(f"4 {tag}: exactly the two base templates admitted",
              len(admitted) == 2 and all(" BASE " in x + " " for x in admitted), "; ".join(admitted))
        if alone:
            not_vap = [x for x in refused if "VAP:" not in x]
            check("4 policy alone: every refusal is the policy's own", not not_vap, "; ".join(not_vap))
    adm = "\n".join(find(secs, "probe 4: the admitted job pod"))
    check("4 admitted job: no name resolves, no token, proxy reachable",
          "NO-RESOLVE" in adm and "RESOLVES\n" not in adm + "\n" and "proxy from t-job: OPEN" in adm
          and "/var/run/secrets: No such file" in adm and "nameserver 127.0.0.1" in adm, adm)
    for sec in ("probe 4: admin adds an ephemeral container (PSA on)", "probe 4: admin adds an ephemeral container (PSA off"):
        txt = "\n".join(find(secs, sec))
        check(f"4 {sec[9:]}: refused by the policy, none added",
              "denied request: only pod creation" in txt and "now: []" in txt, txt)
    check("4 admin relabel refused by the policy",
          "denied request: only pod creation" in "\n".join(find(secs, "probe 4: admin relabels")))

    allowed, rows = set(), 0
    for line in find(secs, "probe 4b:"):
        m = re.match(r"(ALLOWED|DENIED)\s+(.+?)\s{2,}", line)
        if m:
            rows += 1
            if m.group(1) == "ALLOWED":
                allowed.add(m.group(2).strip())
    check("4b launcher rights: exactly the listed ones allowed", rows == 17 and allowed == LAUNCHER_ALLOWED,
          f"{rows} rows, allowed {sorted(allowed)}")

    timing = "\n".join(find(secs, "probe 5:"))
    m = re.search(r"median ([0-9.]+)", timing)
    check("5 box timing measured (12 runs)", m is not None and timing.count("create->ready_ms=") == 12, timing)
    if m:
        print(f"     box create->ready median {float(m.group(1)):.0f} ms")

    life = "\n".join(find(secs, "probe 6:"))
    check("6 volume held by a box, then deleted with its pods; no storage left",
          "Bound" in life and life.count("NotFound") == 2 and "PersistentVolumes left: 0" in life, life)

    print(f"\n{'NO-GO' if fails else 'GO'}: {len(fails)} probe(s) disagree" + (f": {', '.join(fails)}" if fails else ""))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
