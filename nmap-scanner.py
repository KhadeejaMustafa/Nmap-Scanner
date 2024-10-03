import nmap

scanner = nmap.PortScanner()
print("------ Nmap Automation Tool ------")

ip_address = input('Please enter the IP address you wish to scan: ')
print(f'The IP address you entered: {ip_address}')
type(ip_address)

response = input("""\n Select the type of scan you wish to run:
                     1. SYN ACK Scan
                     2. UDP Scan
                     3. Comprehensive Scan
                     4. Operating System Detection\n""")
print(f'The scan type you selected is: {response}')

if response == '1':
    nmap_version = scanner.nmap_version()
    print(f"\nNmap version: {nmap_version[0]}.{nmap_version[1]}")

    # Perform scan
    scanner.scan(ip_address, '1-1024', '-v -sS')

    # Scan information
    scan_info = scanner.scaninfo()
    print("\nScan Information:")
    for key, value in scan_info.items():
     print(f"  {key}: {value}")

    # Print the status of the IP address; up or down
    ip_status = scanner[ip_address].state()
    print(f"\nIP Status: {ip_status}") 
    
    # Extract and print all protocols
    protocols = scanner[ip_address].all_protocols()
    for proto in protocols:
     print(f"\nProtocols: {proto}")

    # List open ports
    open_ports = scanner[ip_address]['tcp'].keys()
    print(f'\nOpen ports: ' )
    for port in open_ports:
     print(f"{port}")



elif response == '2':
  
    nmap_version = scanner.nmap_version()
    print(f"\nNmap version: {nmap_version[0]}.{nmap_version[1]}")

    # Perform UDP scan
    scanner.scan(ip_address, '1-1024', '-v -sU')

    # Scan information
    scan_info = scanner.scaninfo()
    print("\nScan Information:")
    for key, value in scan_info.items():
     print(f"  {key}: {value}")

    # Print the status of the IP address; up or down
    ip_status = scanner[ip_address].state()
    print(f"\nIP Status: {ip_status}") 
    
    # Extract and print all protocols
    protocols = scanner[ip_address].all_protocols()
    for proto in protocols:
     print(f"\nProtocols: {proto}")

    # List open ports
    open_ports = scanner[ip_address]['udp'].keys()
    print(f'\nOpen ports: ' )
    for port in open_ports:
     print(f"{port}")


# Performs comprehensive scan
elif response == '3':

    nmap_version = scanner.nmap_version()
    print(f"\nNmap version: {nmap_version[0]}.{nmap_version[1]}")

    # Perform scan
    scanner.scan(ip_address, '1-1024', '-v -sS -sC -sV -A -O')

    # Scan information
    scan_info = scanner.scaninfo()
    print("\nScan Information:")
    for key, value in scan_info.items():
     print(f"  {key}: {value}")

    # Print the status of the IP address; up or down
    ip_status = scanner[ip_address].state()
    print(f"\nIP Status: {ip_status}") 
    
    # Extract and print all protocols
    protocols = scanner[ip_address].all_protocols()
    for proto in protocols:
     print(f"\nProtocols: {proto}")

    # List open ports
    open_ports = scanner[ip_address]['tcp'].keys()
    print(f'\nOpen ports: ' )
    for port in open_ports:
     print(f"{port}")

# performs os detection
elif response == '4':
 os_detection = scanner.scan(ip_address, arguments='-O')['scan'][ip_address]['osmatch'][0]
 print(f"{os_detection}")

else:
    print("Invalid input.")

