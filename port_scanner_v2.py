import socket
import re
import ipaddress
from common_ports import ports_and_services

def validar_target(target: str) -> dict:
    ip_pattern = r"^(\d\.*)+$"
    if re.match(ip_pattern, target):
        try:
            ipaddress.ip_address(target)
            return {"ip":target,"error":None}
        except ValueError:
            return {"ip":None,"error":"Error: Invalid IP address"}
    else:
        try:
            ip=socket.gethostbyname(target)
            return {"ip":ip,"error":None}
        except socket.gaierror:
            return {"ip":None,"error":"Error: Invalid hostname"} 

def get_name_or_ip(ip: str) -> str:
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except socket.herror:
        return ""

def get_open_ports(target, port_range, verbose = False):
    open_ports = []

    validacionObj = validar_target(target)

    if validacionObj["ip"] is None:
        return validacionObj["error"]
    
    ip_address = validacionObj["ip"]

    
    for port in range(port_range[0], port_range[1]+1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5) 
        result = sock.connect_ex((ip_address, port))  
        
        if result == 0:
            open_ports.append(port)
        sock.close()

    if not verbose:
        return open_ports
    
    ports_str = "\n".join(
        f"{port:<9}{ports_and_services.get(port, 'unknown')}" for port in open_ports
    )

    hostname = get_name_or_ip(ip_address)

    return f"Open ports for {f'{hostname} ({ip_address})' if hostname else ip_address}\nPORT     SERVICE\n{ports_str}"
