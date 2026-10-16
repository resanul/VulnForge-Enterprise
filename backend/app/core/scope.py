import ipaddress
import socket
from urllib.parse import urlparse
from typing import List, Tuple, Optional

# Disallowed dangerous destinations by default
DISALLOWED_METADATA_IPS = [
    ipaddress.ip_network("169.254.169.254/32"),   # AWS/GCP/Azure instance metadata
    ipaddress.ip_network("100.100.100.200/32"),   # Alibaba metadata
    ipaddress.ip_network("169.254.0.0/16"),       # IPv4 Link-Local
    ipaddress.ip_network("fe80::/10"),            # IPv6 Link-Local
    ipaddress.ip_network("127.0.0.0/8"),          # IPv4 Loopback
    ipaddress.ip_network("::1/128"),              # IPv6 Loopback
    ipaddress.ip_network("0.0.0.0/8"),            # Current network
    ipaddress.ip_network("224.0.0.0/4"),          # Multicast
    ipaddress.ip_network("240.0.0.0/4"),          # Reserved
]

class ScopeEnforcementError(Exception):
    pass

def parse_target_to_ips(target: str) -> List[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Resolves target (hostname, URL, IP, or CIDR) into a list of concrete IP addresses."""
    cleaned = target.strip()
    if cleaned.startswith("http://") or cleaned.startswith("https://"):
        parsed = urlparse(cleaned)
        hostname = parsed.hostname or cleaned
    else:
        # Check if port is specified like host:port
        if ":" in cleaned and not cleaned.startswith("[") and "/" not in cleaned:
            # Maybe host:port
            parts = cleaned.split(":")
            hostname = parts[0]
        else:
            hostname = cleaned

    # Check if target is a CIDR notation
    if "/" in hostname:
        try:
            network = ipaddress.ip_network(hostname, strict=False)
            # Limit CIDR expansion to reasonable maximum for safety in resolution
            return list(network.hosts()) if network.num_addresses > 1 else [network.network_address]
        except ValueError as e:
            raise ScopeEnforcementError(f"Invalid CIDR notation: {hostname} ({e})")

    # Check if single IP
    try:
        ip = ipaddress.ip_address(hostname)
        return [ip]
    except ValueError:
        pass

    # If domain / hostname, resolve via DNS
    try:
        resolved_info = socket.getaddrinfo(hostname, None)
        ips = []
        for item in resolved_info:
            sockaddr = item[4]
            ip_str = sockaddr[0]
            ips.append(ipaddress.ip_address(ip_str))
        if not ips:
            raise ScopeEnforcementError(f"Target '{hostname}' could not be resolved to any IP address.")
        # Deduplicate while preserving order
        unique_ips = []
        for ip in ips:
            if ip not in unique_ips:
                unique_ips.append(ip)
        return unique_ips
    except socket.gaierror as e:
        raise ScopeEnforcementError(f"DNS resolution failure for target '{hostname}': {e}")

def validate_scope(
    target: str,
    approved_scopes: List[str],
    allow_loopback_for_testing: bool = False
) -> Tuple[bool, str]:
    """
    Validates that a target is strictly within the user's approved authorization scopes.
    Guarantees that cloud metadata, link-local, and unauthorized networks are rejected.
    """
    if not target or not target.strip():
        return False, "Target cannot be empty"

    if not approved_scopes:
        return False, "No approved scopes configured for organization. Scan rejected."

    try:
        target_ips = parse_target_to_ips(target)
    except ScopeEnforcementError as e:
        return False, str(e)
    except Exception as e:
        return False, f"Target resolution error: {str(e)}"

    # 1. Reject cloud metadata and link-local ranges always
    for ip in target_ips:
        if not allow_loopback_for_testing and ip.is_loopback:
            return False, f"Target IP {ip} is loopback address, which is prohibited without lab test mode."

        for restricted_net in DISALLOWED_METADATA_IPS:
            if not allow_loopback_for_testing and restricted_net == ipaddress.ip_network("127.0.0.0/8"):
                continue
            if ip in restricted_net:
                return False, f"Target IP {ip} falls into restricted infrastructure/metadata range ({restricted_net}). Execution blocked."

    # 2. Check against approved scopes
    approved_networks = []
    approved_hostnames = []
    for s in approved_scopes:
        s_clean = s.strip().lower()
        if not s_clean:
            continue
        try:
            if "/" in s_clean:
                approved_networks.append(ipaddress.ip_network(s_clean, strict=False))
            else:
                approved_networks.append(ipaddress.ip_network(f"{s_clean}/32", strict=False))
        except ValueError:
            # It's a hostname or domain suffix like .corp.internal or example.com
            approved_hostnames.append(s_clean)

    # Validate target matches at least one approved scope
    for ip in target_ips:
        ip_in_scope = False
        for net in approved_networks:
            if ip in net:
                ip_in_scope = True
                break
        
        if not ip_in_scope:
            # Check domain name matching if target was given as hostname/URL
            target_host = target.strip().lower()
            if target_host.startswith("http://") or target_host.startswith("https://"):
                target_host = urlparse(target_host).hostname or target_host
            if ":" in target_host:
                target_host = target_host.split(":")[0]

            for h in approved_hostnames:
                if target_host == h or target_host.endswith(f".{h}"):
                    ip_in_scope = True
                    break

        if not ip_in_scope:
            return False, f"Target IP {ip} ({target}) is outside all approved authorization scopes. Scan prohibited."

    return True, "Target verified within authorized scope."
