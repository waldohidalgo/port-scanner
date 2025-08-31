import port_scanner_v2 as port_scanner

ports = port_scanner.get_open_ports("209.216.230.240", [440, 445], False)
print(ports, "\n")

print("largo:", len(ports))