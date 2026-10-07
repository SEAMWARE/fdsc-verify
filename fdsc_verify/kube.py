"""Thin kubectl wrapper.

kubectl by subprocess rather than the Python client on purpose: it inherits the
kubeconfig, the current context, kubie sessions and any auth plugin for free,
which is exactly what an operator running this from their laptop expects. It is
also what the other scripts in this repo already do.
"""

from __future__ import annotations

import base64
import json
import shutil
import subprocess
from typing import Dict, List, Optional


class KubeError(RuntimeError):
    pass


class KubeUnavailable(KubeError):
    """kubectl is missing or the cluster is unreachable - checks degrade to SKIP."""


class Kube:
    def __init__(self, context: Optional[str] = None, namespace: Optional[str] = None,
                 timeout: int = 30):
        self.context = context
        self.namespace = namespace
        self.timeout = timeout
        self._available: Optional[bool] = None

    # ----------------------------------------------------------------- plumbing

    def _base(self, namespace: Optional[str] = None) -> List[str]:
        cmd = ["kubectl"]
        if self.context:
            cmd += ["--context", self.context]
        ns = namespace or self.namespace
        if ns:
            cmd += ["-n", ns]
        return cmd

    def run(self, *args: str, namespace: Optional[str] = None, check: bool = True) -> str:
        if shutil.which("kubectl") is None:
            raise KubeUnavailable("kubectl not found on PATH")
        proc = subprocess.run(self._base(namespace) + list(args),
                              capture_output=True, timeout=self.timeout)
        if proc.returncode != 0:
            err = proc.stderr.decode("utf-8", "replace").strip()
            if "Unable to connect" in err or "was not found for specified context" in err \
                    or "no configuration has been provided" in err:
                raise KubeUnavailable(err.splitlines()[0] if err else "cluster unreachable")
            if check:
                raise KubeError(err.splitlines()[0] if err else "kubectl failed")
            return ""
        return proc.stdout.decode("utf-8", "replace")

    def available(self) -> bool:
        """Cheap reachability probe, cached, so the runner can skip cluster checks once."""
        if self._available is None:
            try:
                self.run("version", "--request-timeout=10s", "-o", "json")
                self._available = True
            except KubeError:
                self._available = False
        return self._available

    # -------------------------------------------------------------------- reads

    def get_json(self, kind: str, name: str = "", namespace: Optional[str] = None,
                 check: bool = True, selector: Optional[str] = None) -> Optional[dict]:
        """`kubectl get -o json`. `kind` may be a comma-separated list.

        `selector` matters more than it looks: Helm keeps every historical
        revision of a release as its own Secret, each carrying the whole rendered
        manifest, so `get secret -l owner=helm` on a long-lived namespace pulls
        tens of megabytes and looks like a hang. Always narrow with
        `status=deployed`.
        """
        args = ["get", kind]
        if name:
            args.append(name)
        if selector:
            args += ["-l", selector]
        args += ["-o", "json"]
        out = self.run(*args, namespace=namespace, check=check)
        if not out:
            return None
        return json.loads(out)

    def list_names(self, kind: str, namespace: Optional[str] = None) -> List[str]:
        data = self.get_json(kind, namespace=namespace, check=False)
        if not data:
            return []
        return [item["metadata"]["name"] for item in data.get("items", [])]

    def secret(self, name: str, namespace: Optional[str] = None) -> Dict[str, bytes]:
        """Decoded secret data. Returns {} when the secret does not exist."""
        data = self.get_json("secret", name, namespace=namespace, check=False)
        if not data:
            return {}
        return {k: base64.b64decode(v) for k, v in (data.get("data") or {}).items()}

    def configmap(self, name: str, namespace: Optional[str] = None) -> Dict[str, str]:
        data = self.get_json("configmap", name, namespace=namespace, check=False)
        if not data:
            return {}
        return data.get("data") or {}

    def logs(self, workload: str, since: str = "10m", container: Optional[str] = None,
             namespace: Optional[str] = None, tail: int = 4000) -> str:
        args = ["logs", workload, "--since", since, "--tail", str(tail)]
        if container:
            args += ["-c", container]
        try:
            return self.run(*args, namespace=namespace, check=False)
        except KubeError:
            return ""


class PortForward:
    """A `kubectl port-forward` held open for the duration of a `with` block.

    Used to reach the in-cluster APIs (identityhub, trusted-issuers-list) that are
    deliberately not exposed publicly. A port-forward creates nothing in the
    cluster - it is a read-only tunnel - which matters because this tool must be
    safe to point at someone else's environment.

    The local port is chosen by the kernel to avoid collisions when several
    forwards are open at once.
    """

    def __init__(self, kube: "Kube", service: str, remote_port: int,
                 namespace: Optional[str] = None, timeout: int = 20,
                 kind: str = "svc"):
        """`kind` is "svc" unless the port is not on the Service at all.

        contract-management is the case that needed it: its container listens for
        health on 9090 and the Service publishes only 8080, so the management
        endpoint is unreachable through the Service however correct the name is.
        Targeting a pod is a weaker thing to do - a pod is replaceable and the
        Service is the stable address - so it stays opt-in rather than a fallback.
        """
        self.kube = kube
        self.kind = kind
        self.service = service
        self.remote_port = remote_port
        self.namespace = namespace
        self.timeout = timeout
        self.local_port: Optional[int] = None
        self._proc: Optional[subprocess.Popen] = None

    def __enter__(self) -> "PortForward":
        import socket as _socket
        import time

        with _socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            self.local_port = probe.getsockname()[1]

        cmd = self.kube._base(self.namespace) + [
            "port-forward", "%s/%s" % (self.kind, self.service),
            "%d:%d" % (self.local_port, self.remote_port),
        ]
        self._proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

        deadline = time.time() + self.timeout
        while time.time() < deadline:
            if self._proc.poll() is not None:
                err = (self._proc.stderr.read() or b"").decode("utf-8", "replace")
                raise KubeError("port-forward to %s failed: %s"
                                % (self.service, err.strip().splitlines()[:1]))
            try:
                with _socket.create_connection(("127.0.0.1", self.local_port), timeout=0.5):
                    return self
            except OSError:
                time.sleep(0.25)
        self.__exit__(None, None, None)
        raise KubeError("port-forward to %s did not become ready in %ds"
                        % (self.service, self.timeout))

    def __exit__(self, *exc) -> None:
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:  # pragma: no cover
                self._proc.kill()
        self._proc = None

    @property
    def base_url(self) -> str:
        return "http://127.0.0.1:%d" % self.local_port


def parse_properties(text: str) -> Dict[str, str]:
    """Parse a java .properties file.

    Deliberately minimal - no line continuations, no escapes - because the EDC
    config this reads is generated by the chart and uses none of that. Anything
    fancier would be guessing.
    """
    props: Dict[str, str] = {}
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("!"):
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        props[key.strip()] = value.strip()
    return props
