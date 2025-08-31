import socket
from common_ports import ports_and_services
import nmap
import re
import ipaddress


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
    
# target=url or ip address
# port_range=list[lower,upper]
def get_open_ports(target, port_range, verbose = False):
    open_ports = []

    validacionObj = validar_target(target)

    if(validacionObj["ip"] == None):
        return validacionObj["error"]
    
    ip_address = validacionObj["ip"]
    scanner = nmap.PortScanner()

    port_str = f"{port_range[0]}-{port_range[1]}"


    try:
        
        scanner.scan(hosts=ip_address, ports=port_str, arguments='-sT')
        
        if ip_address in scanner.all_hosts():
            for proto in scanner[ip_address].all_protocols():
                ports = scanner[ip_address][proto].keys()
                for port in ports:
                    if scanner[ip_address][proto][port]['state'] == 'open':
                        open_ports.append(port)
            
            open_ports.sort()
    
    except scanner.PortScannerError as e: # type: ignore
        return f"Error with nmap scan: {str(e)}"
    except Exception as e:
        return f"Unexpected error: {str(e)}"

    if not verbose:
        return open_ports
    
    '''
    template
    Open ports for {URL} ({IP address})
    PORT     SERVICE
    {port}   {service name}
    {port}   {service name}
    '''

    
    ports_str = "\n".join(f"{port:<9}{ports_and_services[port]}" for port in open_ports)


    hostname=get_name_or_ip(target)

    return f"Open ports for {f'{hostname} ({ip_address})' if hostname else ip_address}\nPORT     SERVICE\n{ports_str}"