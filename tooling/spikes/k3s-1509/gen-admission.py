"""Print the admission cases for run-admission.sh: two base templates and one change per security-relevant field."""
import copy
import json

IMG='docker.io/library/busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662'
def base(kind):
    sec={"allowPrivilegeEscalation":False,"readOnlyRootFilesystem":True,"capabilities":{"drop":["ALL"]}}
    p={"apiVersion":"v1","kind":"Pod","metadata":{"name":f"t-{kind}","namespace":"jobs","labels":{"zone":kind,"claim":"c9","tenant":"t1"}},
       "spec":{"runtimeClassName":"gvisor-job" if kind=="job" else "gvisor-box","serviceAccountName":"job","automountServiceAccountToken":False,
               "dnsPolicy":"None","dnsConfig":{"nameservers":["127.0.0.1"]},
               "securityContext":{"runAsNonRoot":True,"runAsUser":1000,"runAsGroup":1000,"fsGroup":1000,"seccompProfile":{"type":"RuntimeDefault"}},
               "containers":[{"name":"c","image":IMG,"command":["sleep","3600"],"securityContext":sec,"volumeMounts":[{"name":"work","mountPath":"/work"}]}]}}
    if kind=="job":
        p["spec"]["volumes"]=[{"name":"work","ephemeral":{"volumeClaimTemplate":{"spec":{"accessModes":["ReadWriteOnce"],"storageClassName":"local-path","resources":{"requests":{"storage":"1Gi"}}}}}},
                              {"name":"pass","secret":{"secretName":"pass-c9"}}]
        p["spec"]["containers"][0]["volumeMounts"].append({"name":"pass","mountPath":"/pass","readOnly":True})
    else:
        p["metadata"]["labels"]["job"]="t-job"
        p["spec"]["volumes"]=[{"name":"work","persistentVolumeClaim":{"claimName":"t-job-work"}}]
    return p
def m(kind, name, f):
    p = base(kind)
    f(p)
    p["metadata"]["name"] = f"m-{kind}-{name}"[:60].lower().replace("_", "-")
    return name, p


def C(p):
    return p["spec"]["containers"][0]

cases=[("BASE",base("job")),("BASE",base("box"))]
cases+=[
 m("job","runtime-runc",lambda p:p["spec"].pop("runtimeClassName")),
 m("box","box-with-job-runtime",lambda p:p["spec"].update(runtimeClassName="gvisor-job")),
 m("job","nodeName",lambda p:p["spec"].update(nodeName="k3d-spike1509-server-0")),
 m("job","nodeSelector",lambda p:p["spec"].update(nodeSelector={"pool":"control"})),
 m("job","affinity",lambda p:p["spec"].update(affinity={"nodeAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":{"nodeSelectorTerms":[{"matchExpressions":[{"key":"x","operator":"Exists"}]}]}}})),
 m("job","toleration",lambda p:p["spec"].update(tolerations=[{"key":"pool","operator":"Exists","effect":"NoSchedule"}])),
 m("job","hostNetwork",lambda p:p["spec"].update(hostNetwork=True)),
 m("job","hostPID",lambda p:p["spec"].update(hostPID=True)),
 m("job","hostIPC",lambda p:p["spec"].update(hostIPC=True)),
 m("job","token-automount",lambda p:p["spec"].update(automountServiceAccountToken=True)),
 m("job","token-default",lambda p:p["spec"].pop("automountServiceAccountToken")),
 m("job","other-sa",lambda p:p["spec"].update(serviceAccountName="default")),
 m("job","dns-clusterfirst",lambda p:(p["spec"].pop("dnsPolicy"),p["spec"].pop("dnsConfig"))),
 m("job","dns-nameserver",lambda p:p["spec"].update(dnsConfig={"nameservers":["10.43.0.10"]})),
 m("job","image-tag",lambda p:C(p).update(image="busybox:1.36.1")),
 m("job","command",lambda p:C(p).update(command=["sh","-c","id"])),
 m("job","args",lambda p:C(p).update(args=["x"])),
 m("job","second-container",lambda p:p["spec"]["containers"].append(dict(copy.deepcopy(C(p)),name="d"))),
 m("job","initContainer",lambda p:p["spec"].update(initContainers=[dict(copy.deepcopy(C(p)),name="i")])),
 m("job","shareProcessNamespace",lambda p:p["spec"].update(shareProcessNamespace=True)),
 m("job","hostAliases",lambda p:p["spec"].update(hostAliases=[{"ip":"1.2.3.4","hostnames":["x"]}])),
 m("job","privileged",lambda p:(C(p)["securityContext"].update(privileged=True),C(p)["securityContext"].pop("allowPrivilegeEscalation"))),
 m("job","cap-add",lambda p:C(p)["securityContext"]["capabilities"].update(add=["NET_ADMIN"])),
 m("job","priv-escalation",lambda p:C(p)["securityContext"].update(allowPrivilegeEscalation=True)),
 m("job","rw-rootfs",lambda p:C(p)["securityContext"].update(readOnlyRootFilesystem=False)),
 m("job","run-as-root",lambda p:p["spec"]["securityContext"].update(runAsUser=0,runAsNonRoot=False)),
 m("job","container-runAsUser",lambda p:C(p)["securityContext"].update(runAsUser=2000)),
 m("job","seccomp-unconfined",lambda p:p["spec"]["securityContext"].update(seccompProfile={"type":"Unconfined"})),
 m("job","sysctl",lambda p:p["spec"]["securityContext"].update(sysctls=[{"name":"net.ipv4.ping_group_range","value":"0 0"}])),
 m("job","hostPort",lambda p:C(p).update(ports=[{"containerPort":80,"hostPort":8080}])),
 m("job","hostPath-volume",lambda p:(p["spec"]["volumes"].append({"name":"h","hostPath":{"path":"/"}}),C(p)["volumeMounts"].append({"name":"h","mountPath":"/h"}))),
 m("job","emptyDir-volume",lambda p:p["spec"]["volumes"].append({"name":"e","emptyDir":{}})),
 m("job","projected-token",lambda p:p["spec"]["volumes"].append({"name":"tok","projected":{"sources":[{"serviceAccountToken":{"path":"t","audience":"proxy"}}]}})),
 m("job","foreign-secret",lambda p:p["spec"]["volumes"][1]["secret"].update(secretName="pass-OTHER")),
 m("job","other-storageclass",lambda p:p["spec"]["volumes"][0]["ephemeral"]["volumeClaimTemplate"]["spec"].update(storageClassName="other")),
 m("job","subPath",lambda p:C(p)["volumeMounts"][0].update(subPath="sub")),
 m("job","mountPropagation",lambda p:C(p)["volumeMounts"][0].update(mountPropagation="HostToContainer")),
 m("box","box-secret",lambda p:(p["spec"]["volumes"].append({"name":"pass","secret":{"secretName":"pass-c9"}}))),
 m("box","box-foreign-pvc",lambda p:p["spec"]["volumes"][0]["persistentVolumeClaim"].update(claimName="vjob-work")),
 m("box","no-claim-label",lambda p:p["metadata"]["labels"].pop("claim")),
]
for name, p in cases:
    print(json.dumps({"case": name, "pod": p}))
