#!/usr/bin/env python3
"""
Kubernetes Enumeration Tool.

Enumerates Kubernetes clusters, namespaces, pods, services, deployments,
secrets (metadata only), configmaps, RBAC roles/bindings, and detects
security misconfigurations.

Usage:
    # Using kubeconfig
    python k8s_enum.py

    # With explicit token and server
    python k8s_enum.py --token "eyJ..." --server "https://k8s-api:6443"

    # With certificate authority
    python k8s_enum.py --server "https://k8s-api:6443" --token "..." --ca /path/to/ca.crt

    # Specific namespace
    python k8s_enum.py --namespace "production"
"""

import argparse
import base64
import json
import os
import sys
import ssl
from urllib.parse import urljoin

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning

    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    print("[!] Modul 'requests' tidak ditemukan. Install: pip install requests")
    sys.exit(1)


def load_kubeconfig(path=None):
    """Load Kubernetes configuration from kubeconfig file."""
    kube_path = path or os.path.expanduser("~/.kube/config")
    if not os.path.exists(kube_path):
        print(f"[-] Kubeconfig tidak ditemukan: {kube_path}")
        return None

    try:
        import yaml
    except ImportError:
        print("[!] PyYAML tidak ditemukan. Install: pip install pyyaml")
        return None

    with open(kube_path, "r") as f:
        cfg = yaml.safe_load(f)

    contexts = cfg.get("contexts", [])
    current_ctx = cfg.get("current-context", "")

    print(f"[*] Memuat kubeconfig: {kube_path}")
    print(f"[*] Current context: {current_ctx}")

    ctx_info = None
    for ctx in contexts:
        if ctx.get("name") == current_ctx:
            ctx_info = ctx.get("context", {})
            break

    if not ctx_info:
        print(f"[!] Context '{current_ctx}' tidak ditemukan dalam kubeconfig")
        print(f"[*] Context yang tersedia: {[c['name'] for c in contexts]}")
        return None

    cluster_name = ctx_info.get("cluster", "")
    user_name = ctx_info.get("user", "")
    namespace = ctx_info.get("namespace", "default")

    clusters = {c["name"]: c.get("cluster", {}) for c in cfg.get("clusters", [])}
    users = {u["name"]: u.get("user", {}) for u in cfg.get("users", [])}

    cluster = clusters.get(cluster_name, {})
    user = users.get(user_name, {})

    result = {
        "server": cluster.get("server", ""),
        "namespace": namespace,
        "ca_file": cluster.get("certificate-authority"),
        "ca_data": cluster.get("certificate-authority-data"),
        "token": user.get("token"),
        "client_cert": user.get("client-certificate"),
        "client_key": user.get("client-key"),
    }

    if not result["token"] and user.get("exec"):
        print("[*] Mendeteksi exec-based auth, mencoba mengeksekusi...")
        try:
            import subprocess
            import tempfile

            exec_cfg = user["exec"]
            cmd = exec_cfg.get("command", "")
            args = exec_cfg.get("args", [])
            env = os.environ.copy()
            for e in exec_cfg.get("env", []):
                env[e["name"]] = e["value"]

            proc = subprocess.run(
                [cmd] + args,
                capture_output=True,
                text=True,
                env=env,
                timeout=15,
            )
            if proc.returncode == 0:
                cred = json.loads(proc.stdout)
                result["token"] = cred.get("status", {}).get("token", "")
                if result["token"]:
                    print("[+] Token didapatkan dari exec credential plugin")
            else:
                print(f"[!] Gagal eksekusi credential plugin: {proc.stderr[:200]}")
        except Exception as e:
            print(f"[!] Gagal mendapatkan token exec: {e}")

    return result


def setup_session(
    server,
    token=None,
    ca_file=None,
    ca_data=None,
    client_cert=None,
    client_key=None,
    verify_ssl=True,
):
    """Set up requests session for Kubernetes API."""
    session = requests.Session()
    session.verify = verify_ssl

    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    if ca_file and os.path.exists(ca_file):
        session.verify = ca_file
    elif ca_data:
        import tempfile

        decoded = base64.b64decode(ca_data)
        with tempfile.NamedTemporaryFile(delete=False, suffix=".crt") as tmp:
            tmp.write(decoded)
            session.verify = tmp.name
    elif not verify_ssl:
        session.verify = False

    if client_cert and client_key:
        session.cert = (client_cert, client_key)

    session.headers.update(headers)
    return session


def k8s_get(session, server, path, namespace=None, label_selector=None):
    """Make GET request to Kubernetes API."""
    url = server.rstrip("/") + path
    params = {}
    if namespace:
        params["namespace"] = namespace
    if label_selector:
        params["labelSelector"] = label_selector
    try:
        resp = session.get(
            url,
            params=params if params else None,
            timeout=30,
            verify=session.verify if session.verify else False,
        )
        if resp.status_code == 200:
            return resp.json()
        elif resp.status_code == 401:
            print(f"[!] Unauthorized (HTTP 401) untuk {path}")
            return None
        elif resp.status_code == 403:
            print(f"[!] Forbidden (HTTP 403) untuk {path}")
            return None
        elif resp.status_code == 404:
            print(f"[-] Not found (HTTP 404) untuk {path}")
            return None
        else:
            print(f"[!] HTTP {resp.status_code} untuk {path}")
            return None
    except requests.exceptions.SSLError:
        print(f"[!] SSL Error. Coba dengan --insecure")
        return None
    except requests.exceptions.ConnectionError:
        print(f"[!] Tidak dapat terhubung ke {server}")
        return None
    except Exception as e:
        print(f"[!] Error: {e}")
        return None


def check_api_server(session, server):
    """Check if Kubernetes API server is accessible."""
    print(f"[*] Memeriksa koneksi ke API server: {server}")
    data = k8s_get(session, server, "/api")
    if data:
        print(f"[+] API server dapat diakses")
        version_data = k8s_get(session, server, "/version")
        if version_data:
            print(f"[+] Versi Kubernetes: {version_data.get('gitVersion', '?')}")
        return True
    return False


def enum_namespaces(session, server):
    """Enumerate namespaces."""
    print("\n--- Enumerasi Namespaces ---")
    data = k8s_get(session, server, "/api/v1/namespaces")
    if not data:
        return []
    items = data.get("items", [])
    print(f"[+] Namespaces: {len(items)}")
    for ns in items:
        name = ns["metadata"]["name"]
        labels = ns["metadata"].get("labels", {})
        print(f"  [*] {name} (labels={labels})")
    return items


def enum_pods(session, server, namespace=None):
    """Enumerate pods."""
    target = f"namespace={namespace}" if namespace else "semua namespace"
    print(f"\n--- Enumerasi Pods ({target}) ---")
    path = f"/api/v1/namespaces/{namespace}/pods" if namespace else "/api/v1/pods"
    data = k8s_get(session, server, path)
    if not data:
        return []

    items = data.get("items", [])
    print(f"[+] Pods: {len(items)}")
    risks = []

    for pod in items:
        ns = pod["metadata"]["namespace"]
        name = pod["metadata"]["name"]
        status = pod.get("status", {}).get("phase", "?")
        host_net = pod["spec"].get("hostNetwork", False)
        host_pid = pod["spec"].get("hostPID", False)
        host_ipc = pod["spec"].get("hostIPC", False)
        sa = pod["spec"].get("serviceAccountName", "default")

        flags = []
        is_privileged = False

        for container in pod["spec"].get("containers", []):
            sc = container.get("securityContext", {})
            if sc.get("privileged"):
                is_privileged = True
                flags.append("[!] PRIVILEGED")

            caps_add = sc.get("capabilities", {}).get("add", [])
            if "SYS_ADMIN" in caps_add:
                flags.append("[!] SYS_ADMIN")
            if "NET_ADMIN" in caps_add:
                flags.append("[!] NET_ADMIN")

            for vm in container.get("volumeMounts", []):
                mp = vm.get("mountPath", "")
                if mp in ("/var/run/docker.sock", "/run/containerd/containerd.sock"):
                    flags.append("[!] DOCKER-SOCK-MOUNT")
                if mp.startswith("/host"):
                    flags.append("[!] HOST-MOUNT")

        for vol in pod["spec"].get("volumes", []):
            hp = vol.get("hostPath")
            if hp:
                hp_path = hp.get("path", "")
                if hp_path in ("/", "/etc", "/var", "/proc", "/sys", "/root"):
                    flags.append(f"[!] HOSTPATH({hp_path})")

        if host_net:
            flags.append("[!] HOST-NETWORK")
            risks.append(f"{ns}/{name}: host network namespace")
        if host_pid:
            flags.append("[!] HOST-PID")
            risks.append(f"{ns}/{name}: host PID namespace")
        if is_privileged:
            risks.append(f"{ns}/{name}: privileged pod")
        if "HOSTPATH" in " ".join(flags):
            risks.append(f"{ns}/{name}: hostPath mount")

        risk_str = " " + " ".join(flags) if flags else ""
        pfx = "[!]" if flags else "[*]"
        print(f"  {pfx} {ns}/{name} ({status}) | SA={sa}{risk_str}")

    if risks:
        print(f"\n[!] Ditemukan {len(risks)} risiko keamanan pod:")
        for r in risks:
            print(f"  [!] {r}")

    return items


def enum_services(session, server, namespace=None):
    """Enumerate services."""
    target = f"namespace={namespace}" if namespace else "semua namespace"
    print(f"\n--- Enumerasi Services ({target}) ---")
    path = f"/api/v1/namespaces/{namespace}/services" if namespace else "/api/v1/services"
    data = k8s_get(session, server, path)
    if not data:
        return []
    items = data.get("items", [])
    print(f"[+] Services: {len(items)}")
    for svc in items:
        ns = svc["metadata"]["namespace"]
        name = svc["metadata"]["name"]
        svc_type = svc["spec"].get("type", "ClusterIP")
        cluster_ip = svc["spec"].get("clusterIP", "None")
        external_ips = svc["spec"].get("externalIPs", [])
        ports = [f"{p.get('port')}/{p.get('protocol')}" for p in svc["spec"].get("ports", [])]
        pfx = "[!]" if svc_type == "LoadBalancer" and external_ips else "[*]"
        print(
            f"  {pfx} {ns}/{name} ({svc_type}) | {cluster_ip} | ports={ports} | ext={external_ips}"
        )
    return items


def enum_deployments(session, server, namespace=None):
    """Enumerate deployments."""
    target = f"namespace={namespace}" if namespace else "semua namespace"
    print(f"\n--- Enumerasi Deployments ({target}) ---")
    path = (
        f"/apis/apps/v1/namespaces/{namespace}/deployments"
        if namespace
        else "/apis/apps/v1/deployments"
    )
    data = k8s_get(session, server, path)
    if not data:
        return []
    items = data.get("items", [])
    print(f"[+] Deployments: {len(items)}")
    for dep in items:
        ns = dep["metadata"]["namespace"]
        name = dep["metadata"]["name"]
        replicas = dep["status"].get("replicas", 0)
        ready = dep["status"].get("readyReplicas", 0)
        print(f"  [*] {ns}/{name} (ready={ready}/{replicas})")
    return items


def enum_secrets_meta(session, server, namespace=None):
    """Enumerate secrets metadata only (no values)."""
    target = f"namespace={namespace}" if namespace else "semua namespace"
    print(f"\n--- Enumerasi Secrets (metadata only) ({target}) ---")
    path = f"/api/v1/namespaces/{namespace}/secrets" if namespace else "/api/v1/secrets"
    data = k8s_get(session, server, path)
    if not data:
        return []
    items = data.get("items", [])
    print(f"[+] Secrets: {len(items)}")
    for s in items:
        ns = s["metadata"]["namespace"]
        name = s["metadata"]["name"]
        stype = s.get("type", "Opaque")
        keys = list(s.get("data", {}).keys())
        labels = s["metadata"].get("labels", {})
        print(f"  [*] {ns}/{name} (type={stype}) | keys={keys[:5]}{'...' if len(keys) > 5 else ''}")
        if labels:
            print(f"      labels={labels}")
    return items


def enum_configmaps(session, server, namespace=None):
    """Enumerate configmaps."""
    target = f"namespace={namespace}" if namespace else "semua namespace"
    print(f"\n--- Enumerasi ConfigMaps ({target}) ---")
    path = f"/api/v1/namespaces/{namespace}/configmaps" if namespace else "/api/v1/configmaps"
    data = k8s_get(session, server, path)
    if not data:
        return []
    items = data.get("items", [])
    print(f"[+] ConfigMaps: {len(items)}")
    for cm in items[:20]:
        ns = cm["metadata"]["namespace"]
        name = cm["metadata"]["name"]
        data_keys = list(cm.get("data", {}).keys())
        print(f"  [*] {ns}/{name} | keys={data_keys[:5]}{'...' if len(data_keys) > 5 else ''}")
    if len(items) > 20:
        print(f"  ... dan {len(items) - 20} configmaps lainnya")
    return items


def enum_rbac(session, server, namespace=None):
    """Enumerate RBAC roles and rolebindings."""
    print("\n--- Enumerasi RBAC ---")

    print("\n[*] Roles:")
    roles_path = (
        f"/apis/rbac.authorization.k8s.io/v1/namespaces/{namespace}/roles"
        if namespace
        else "/apis/rbac.authorization.k8s.io/v1/roles"
    )
    roles_data = k8s_get(session, server, roles_path)
    if roles_data:
        items = roles_data.get("items", [])
        print(f"[+] Roles: {len(items)}")
        for r in items:
            ns = r["metadata"]["namespace"]
            name = r["metadata"]["name"]
            rules = r.get("rules", [])
            has_wildcard = any("*" in str(rule.get("resources", [])) for rule in rules)
            pfx = "[!]" if has_wildcard else "[*]"
            print(f"  {pfx} {ns}/{name} (rules={len(rules)}){' WILDCARD' if has_wildcard else ''}")

    print("\n[*] RoleBindings:")
    rb_path = (
        f"/apis/rbac.authorization.k8s.io/v1/namespaces/{namespace}/rolebindings"
        if namespace
        else "/apis/rbac.authorization.k8s.io/v1/rolebindings"
    )
    rb_data = k8s_get(session, server, rb_path)
    if rb_data:
        items = rb_data.get("items", [])
        print(f"[+] RoleBindings: {len(items)}")
        for rb in items:
            ns = rb["metadata"]["namespace"]
            name = rb["metadata"]["name"]
            role_ref = rb.get("roleRef", {})
            subjects = rb.get("subjects", [])
            subj_str = ", ".join(s.get("name", "?") for s in subjects[:3])
            print(
                f"  [*] {ns}/{name} -> {role_ref.get('kind','?')}/{role_ref.get('name','?')} | subjects=[{subj_str}]"
            )

    print("\n[*] ClusterRoles:")
    cr_data = k8s_get(session, server, "/apis/rbac.authorization.k8s.io/v1/clusterroles")
    if cr_data:
        items = cr_data.get("items", [])
        dangerous = [
            cr
            for cr in items
            if any(
                "*" in str(rule.get("resources", [])) or "*" in str(rule.get("verbs", []))
                for rule in cr.get("rules", [])
            )
        ]
        print(f"[+] ClusterRoles: {len(items)} (dangerous={len(dangerous)})")
        for cr in items[:15]:
            name = cr["metadata"]["name"]
            is_dangerous = name in [d["metadata"]["name"] for d in dangerous]
            pfx = "[!]" if is_dangerous else "[*]"
            print(f"  {pfx} {name}")
        if len(items) > 15:
            print(f"  ... dan {len(items) - 15} clusterroles lainnya")

    print("\n[*] ClusterRoleBindings:")
    crb_data = k8s_get(session, server, "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings")
    if crb_data:
        items = crb_data.get("items", [])
        print(f"[+] ClusterRoleBindings: {len(items)}")
        for crb in items:
            name = crb["metadata"]["name"]
            role_ref = crb.get("roleRef", {})
            subjects = crb.get("subjects", [])
            subj_str = ", ".join(s.get("name", "?") for s in subjects[:3])
            print(
                f"  [*] {name} -> {role_ref.get('kind','?')}/{role_ref.get('name','?')} | subjects=[{subj_str}]"
            )


def check_service_token(session, server):
    """Check if running inside a pod with available service account token."""
    sa_token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
    namespace_path = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
    if os.path.exists(sa_token_path):
        print(f"[+] Menjalankan di dalam pod Kubernetes!")
        try:
            with open(namespace_path, "r") as f:
                ns = f.read().strip()
            print(f"[+] Namespace: {ns}")
            with open(sa_token_path, "r") as f:
                token = f.read().strip()
            print(f"[+] Service account token tersedia ({len(token)} chars)")
            return {"in_pod": True, "namespace": ns, "token": token}
        except Exception as e:
            print(f"[!] Error membaca SA token: {e}")
    else:
        print("[-] Tidak berjalan di dalam pod Kubernetes")
    return None


def check_exposed_dashboard(session, server):
    """Check for exposed Kubernetes dashboard."""
    print("\n[*] Memeriksa Kubernetes Dashboard...")
    dash_svc = k8s_get(session, server, "/api/v1/namespaces/kubernetes-dashboard/services")
    if dash_svc:
        items = dash_svc.get("items", [])
        for svc in items:
            if svc["spec"].get("type") == "LoadBalancer":
                print(f"[!] Dashboard terpapar via LoadBalancer: {svc['metadata']['name']}")
    else:
        print("[-] Kubernetes dashboard namespace tidak ditemukan (aman)")


def main():
    parser = argparse.ArgumentParser(
        description="Kubernetes Enumeration Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Contoh:
  python k8s_enum.py
  python k8s_enum.py --token "eyJ..." --server "https://k8s-api:6443"
  python k8s_enum.py --server "https://k8s-api:6443" --token "..." --ca ca.crt
  python k8s_enum.py --namespace "production"
  python k8s_enum.py --insecure
  python k8s_enum.py --output results.json
        """,
    )
    parser.add_argument("--kubeconfig", help="Path ke file kubeconfig")
    parser.add_argument("--server", help="URL Kubernetes API server")
    parser.add_argument("--token", help="Bearer token untuk autentikasi")
    parser.add_argument("--ca", help="Path ke Certificate Authority file")
    parser.add_argument("--cert", help="Path ke client certificate")
    parser.add_argument("--key", help="Path ke client key")
    parser.add_argument("--namespace", help="Batasi ke namespace spesifik")
    parser.add_argument("--insecure", action="store_true", help="Skip TLS verification")
    parser.add_argument("--output", help="Simpan hasil ke file JSON")
    args = parser.parse_args()

    print("=" * 60)
    print("  Kubernetes Enumeration Tool")
    print("=" * 60)

    kube_data = None
    if not args.server:
        kube_data = load_kubeconfig(args.kubeconfig)
        if kube_data:
            server = kube_data["server"]
            token = kube_data["token"]
            ca_file = kube_data.get("ca_file")
            ca_data = kube_data.get("ca_data")
            client_cert = kube_data.get("client_cert")
            client_key = kube_data.get("client_key")
            ns = kube_data.get("namespace", "default")
        else:
            print("\n[*] Kubeconfig tidak tersedia. Memeriksa apakah berjalan di dalam pod...")
            pod_info = check_service_token(None, None)
            if pod_info:
                server = "https://kubernetes.default.svc"
                token = pod_info["token"]
                ca_file = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
                ns = pod_info["namespace"]
                client_cert = None
                client_key = None
                ca_data = None
            else:
                print("[!] Tidak dapat menemukan kredensial Kubernetes")
                print("[*] Gunakan --server dan --token untuk koneksi manual")
                sys.exit(1)
    else:
        server = args.server
        token = args.token
        ca_file = args.ca
        ca_data = None
        client_cert = args.cert
        client_key = args.key
        ns = args.namespace or "default"

    namespace = args.namespace or ns
    verify_ssl = not args.insecure
    if args.insecure:
        print("[!] SSL verification dimatikan!")

    session = setup_session(
        server,
        token=token,
        ca_file=ca_file,
        ca_data=ca_data,
        client_cert=client_cert,
        client_key=client_key,
        verify_ssl=verify_ssl,
    )

    if not check_api_server(session, server):
        print("[!] Gagal terhubung ke API server")
        sys.exit(1)

    results = {}
    results["namespaces"] = enum_namespaces(session, server)

    if namespace and namespace != "all":
        print(f"\n[*] Fokus pada namespace: {namespace}")
        results["pods"] = enum_pods(session, server, namespace)
        results["services"] = enum_services(session, server, namespace)
        results["deployments"] = enum_deployments(session, server, namespace)
        results["secrets"] = enum_secrets_meta(session, server, namespace)
        results["configmaps"] = enum_configmaps(session, server, namespace)
    else:
        results["pods"] = enum_pods(session, server)
        results["services"] = enum_services(session, server)
        results["deployments"] = enum_deployments(session, server)
        results["secrets"] = enum_secrets_meta(session, server)
        results["configmaps"] = enum_configmaps(session, server)

    enum_rbac(session, server, namespace if namespace != "all" else None)
    check_service_token(session, server)
    check_exposed_dashboard(session, server)

    print("\n--- Ringkasan Risiko ---")
    pods = results["pods"] or []
    privileged = 0
    host_net = 0
    host_pid = 0
    for pod in pods:
        spec = pod.get("spec", {})
        if spec.get("hostNetwork"):
            host_net += 1
        if spec.get("hostPID"):
            host_pid += 1
        for c in spec.get("containers", []):
            if c.get("securityContext", {}).get("privileged"):
                privileged += 1

    print(f"[!] Pods privileged: {privileged}")
    print(f"[!] Pods hostNetwork: {host_net}")
    print(f"[!] Pods hostPID: {host_pid}")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\n[+] Hasil disimpan ke: {args.output}")

    print("\n[*] Selesai.")


if __name__ == "__main__":
    main()
