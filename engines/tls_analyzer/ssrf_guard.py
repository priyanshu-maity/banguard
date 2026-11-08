import ipaddress
import socket


class UnsafeAddressError(Exception):
    pass

def resolve_public_ip(host: str, port: int) -> str:
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    if not infos:
        raise socket.gaierror(f"no addresses for {host}")

    addresses = []
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split("%")[0])
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        if not ip.is_global:
            raise UnsafeAddressError(f"{host} resolves to non-public address {ip}")
        addresses.append(str(ip))
    return addresses[0]