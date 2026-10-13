"""Fail-closed URL and Docker checks; no arbitrary target input accepted."""
import ipaddress
import json
import re
import socket
from urllib.parse import urlsplit

TARGET = "vulnerable-baseline"
PATHS = ("/actuator/health", "/login", "/api/articles", "/api/users", "/api/csrf")
PORT = 8080
LABEL = "com.example.java-devsecops-lab.phase4"


def check_url(url, host, target=TARGET):
    if target != TARGET or not isinstance(url, str) or len(url) > 512:
        raise ValueError("Unknown target")
    if re.search(r"[%\\\s\x00-\x1f\x7f]", url):
        raise ValueError("Encoded, ambiguous or control-character URL")
    parsed = urlsplit(url)
    if (parsed.scheme != "http" or parsed.netloc != f"{host}:{PORT}" or
            parsed.hostname != host or parsed.port != PORT or parsed.username or parsed.password or
            parsed.query or parsed.fragment or parsed.path not in PATHS):
        raise ValueError("URL outside exact authorized scope")
    return parsed.path


def check_address(address, subnet):
    ip = ipaddress.ip_address(address)
    network = ipaddress.ip_network(subnet)
    if ip.version != 4 or not ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip not in network:
        raise ValueError("Address outside isolated Docker network")
    if ip in (network.network_address, network.broadcast_address):
        raise ValueError("Invalid endpoint address")
    return str(ip)


def resolve_exact(host, expected_ip, resolver=socket.getaddrinfo):
    addresses = {entry[4][0] for entry in resolver(host, PORT, type=socket.SOCK_STREAM)}
    if addresses != {expected_ip}:
        raise ValueError("DNS resolution changed or ambiguous")


def reject_redirect(status, location):
    if 300 <= status < 400 or location:
        raise ValueError("Redirect refused; no follow-up request sent")


def validate_network(data, name, run_id, members):
    if (data["Name"] != name or data["Driver"] != "bridge" or data["Internal"] is not True or
            data.get("EnableIPv6") or data.get("Labels", {}).get(LABEL) != run_id):
        raise ValueError("Untrusted Docker network")
    configs = data["IPAM"]["Config"]
    if len(configs) != 1 or ipaddress.ip_network(configs[0]["Subnet"]).version != 4:
        raise ValueError("Unexpected Docker subnet")
    if {v["Name"] for v in data.get("Containers", {}).values()} != set(members):
        raise ValueError("Foreign container on scan network")
    return configs[0]["Subnet"]


def validate_container(data, name, run_id, image_id, networks, mounts=None):
    if (data["Name"] != "/" + name or not data["State"]["Running"] or
            data["Config"].get("Labels", {}).get(LABEL) != run_id or data["Image"] != image_id or
            set(data["NetworkSettings"]["Networks"]) != set(networks) or
            data["HostConfig"].get("Privileged") or data["HostConfig"].get("PortBindings") or
            data["HostConfig"].get("NetworkMode") in ("host", "container") or
            data["HostConfig"].get("CapAdd") or not data["HostConfig"].get("ReadonlyRootfs")):
        raise ValueError("Container identity/isolation mismatch")
    if mounts is not None:
        actual = {(m["Source"].replace("\\", "/").lower(), m["Destination"], m["RW"]) for m in data["Mounts"] if m["Type"] == "bind"}
        wanted = {(source.replace("\\", "/").lower(), dest, rw) for source, dest, rw in mounts}
        if actual != wanted:
            raise ValueError("Application content mounts changed")
    return {n: check_address(data["NetworkSettings"]["Networks"][n]["IPAddress"], subnet)
            for n, subnet in networks.items()}
