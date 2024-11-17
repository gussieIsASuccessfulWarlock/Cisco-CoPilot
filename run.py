import sys
import ipaddress

try:
    from rich import print
except ImportError:
    print("The 'rich' module is required for this script. Please install it using 'pip install rich'.")
    sys.exit(1)

switchConfs = []
routerConfs = []

def prompt(text, example=None):
    while True:
        user_input = input(text)
        if user_input.strip() == '?':
            if example:
                print(f"Example: {example}")
            else:
                print("No example available.")
        else:
            return user_input

def get_subnet_mask(networkSubnet):
    networkSubnet = networkSubnet.strip()
    if networkSubnet.startswith('/'):
        networkSubnet = networkSubnet[1:]
    try:
        prefix_length = int(networkSubnet)
        if 0 <= prefix_length <= 32:
            net = ipaddress.IPv4Network('0.0.0.0/' + networkSubnet)
            return str(net.netmask)
    except ValueError:
        # Try to validate as subnet mask
        try:
            net = ipaddress.IPv4Network('0.0.0.0/' + networkSubnet)
            return networkSubnet
        except ValueError:
            return None
    return None

def checkIP(ip):
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ipaddress.AddressValueError:
        return False

def get_network_info(ip_address, subnet_mask):
    try:
        ip_network = ipaddress.IPv4Network(f"{ip_address}/{subnet_mask}", strict=False)
        network_address = str(ip_network.network_address)
        broadcast_address = str(ip_network.broadcast_address)
        first_available_address = str(ip_network.network_address + 1)
        last_available_address = str(ip_network.broadcast_address - 1)
        return [network_address, broadcast_address, first_available_address, last_available_address]
    except ValueError:
        return [None, None, None, None]

def shortenInterfaces(interfaces):
    netInterfaces = []
    for i in interfaces:
        i = i.strip()
        i = i.replace("fe", "FastEthernet")
        i = i.replace("gi", "GigabitEthernet")
        i = i.replace("se", "Serial")
        netInterfaces.append(i)
    return netInterfaces

def outputCiscoCode(code, device):
    global switchConfs, routerConfs
    code = code.strip()
    if device == "router":
        routerConfs.append(code)
    elif device == "switch":
        switchConfs.append(code)
    print(code)

def autoDHCP(name=None, networkAddress=None, networkSubnet=None, networkDNSServer=None, domainName=None):
    if not name:
        name = prompt("Name Of Pool: ", "ExamplePool")
    if not networkAddress:
        networkAddress = prompt("Network Address: ", "192.168.1.0")
    if not networkSubnet:
        networkSubnet_input = prompt("Network Subnet (Subnet Mask or CIDR, e.g., /24): ", "/24")
        networkSubnet = get_subnet_mask(networkSubnet_input)
        if not networkSubnet:
            print("Invalid subnet mask or CIDR notation.")
            return
    if not networkDNSServer:
        networkDNSServer = prompt("DNS Server: ", "8.8.8.8")
    if not domainName:
        domainName = prompt("Domain Name: ", "example.com")

    network_info = get_network_info(networkAddress, networkSubnet)
    if None in network_info:
        print("Invalid network address or subnet mask.")
        return
    network_addr = network_info[0]
    first_ip = network_info[2]
    last_ip = network_info[3]

    print("\n[orchid2]Generation: (Router Configurations)[/orchid2]\n")
    outputCiscoCode(f"ip dhcp excluded-address {first_ip} {last_ip}", "router")
    outputCiscoCode(f"ip dhcp pool {name.replace(' ', '_')}", "router")
    outputCiscoCode(f"   network {network_addr} {networkSubnet}", "router")
    outputCiscoCode(f"   default-router {first_ip}", "router")
    outputCiscoCode(f"   dns-server {networkDNSServer}", "router")
    outputCiscoCode(f"   domain-name {domainName}", "router")
    outputCiscoCode(f"   exit", "router")

def autoVLAN(number=None, name=None, networkAddress=None, networkSubnet=None, routerInterface=None, switchPortsOnVLAN=None):
    if not number:
        number = prompt("VLAN Number: ", "10")
    if not name:
        name = prompt("VLAN Name: ", "Sales_VLAN")
    if not networkAddress:
        networkAddress = prompt("Network Address: ", "192.168.10.0")
    if not networkSubnet:
        networkSubnet_input = prompt("Network Subnet (Subnet Mask or CIDR, e.g., /24): ", "/24")
        networkSubnet = get_subnet_mask(networkSubnet_input)
        if not networkSubnet:
            print("Invalid subnet mask or CIDR notation.")
            return
    if not routerInterface:
        routerInterface = prompt("Router Interface (e.g., GigabitEthernet0/0/0): ", "GigabitEthernet0/0/0").strip()
        if not routerInterface:
            routerInterface = "GigabitEthernet0/0/0"
    if not switchPortsOnVLAN:
        ports_input = prompt("Switch Ports on VLAN (comma-separated, e.g., FastEthernet0/1, FastEthernet0/2): ", "FastEthernet0/1, FastEthernet0/2")
        switchPortsOnVLAN = shortenInterfaces(ports_input.replace(',', ' ').split())

    network_info = get_network_info(networkAddress, networkSubnet)
    if None in network_info:
        print("Invalid network address or subnet mask.")
        return
    vlan_interface_ip = network_info[2]

    print("\n[orchid2]Generation: (Router Configurations)[/orchid2]\n")
    outputCiscoCode(f"interface {routerInterface}.{number}", "router")
    outputCiscoCode(f"   encapsulation dot1Q {number}", "router")
    outputCiscoCode(f"   ip address {vlan_interface_ip} {networkSubnet}", "router")
    outputCiscoCode(f"   no shutdown", "router")
    outputCiscoCode(f"   exit", "router")

    print("\n[orchid2]Generation: (Switch Configurations)[/orchid2]\n")
    outputCiscoCode(f"vlan {number}", "switch")
    outputCiscoCode(f"   name {name.replace(' ', '_')}", "switch")
    outputCiscoCode(f"   exit", "switch")
    for port in switchPortsOnVLAN:
        outputCiscoCode(f"interface {port}", "switch")
        outputCiscoCode(f"   switchport mode access", "switch")
        outputCiscoCode(f"   switchport access vlan {number}", "switch")
        outputCiscoCode(f"   no shutdown", "switch")
        outputCiscoCode(f"   exit", "switch")
    outputCiscoCode(f"interface {routerInterface}", "switch")
    outputCiscoCode(f"   switchport trunk encapsulation dot1q", "switch")
    outputCiscoCode(f"   switchport mode trunk", "switch")
    outputCiscoCode(f"   no shutdown", "switch")
    outputCiscoCode(f"   exit", "switch")

def autoStandardACL(listName=None, aceNum=None, rule=None, sourceAddr=None, sourceMask=None):
    if not listName:
        listName = prompt("List Name: ", "Standard_ACL")
    if not aceNum:
        aceNum = prompt("ACE number: ", "10")
    if not rule:
        rule = prompt("ACE rule (deny | permit | remark text): ", "permit")
    if not sourceAddr:
        sourceAddr = prompt("Source Address: ", "192.168.1.0")
    if not sourceMask:
        sourceMask_input = prompt("Source Network Subnet (Subnet Mask or CIDR, e.g., /24): ", "/24")
        sourceMask = get_subnet_mask(sourceMask_input)
        if not sourceMask:
            print("Invalid subnet mask or CIDR notation.")
            return

    wildcard_mask = '.'.join([str(255 - int(octet)) for octet in sourceMask.split('.')])

    print("\n[orchid2]Generation: (Router Configurations)[/orchid2]\n")
    outputCiscoCode(f"ip access-list standard {listName}", "router")
    outputCiscoCode(f"   {aceNum} {rule} {sourceAddr} {wildcard_mask}", "router")
    outputCiscoCode(f"   exit", "router")

def autoExtendedACL(listName=None, aceNum=None, rule=None, protocol=None, sourceAddr=None, sourceMask=None, dstAddr=None, dstMask=None):
    if not listName:
        listName = prompt("List Name: ", "Extended_ACL")
    if not aceNum:
        aceNum = prompt("ACE number: ", "10")
    if not rule:
        rule = prompt("ACE rule (deny | permit | remark text): ", "deny")
    if not protocol:
        protocol = prompt("Protocol (tcp | udp | icmp | ip): ", "tcp")
    if not sourceAddr:
        sourceAddr = prompt("Source Address: ", "192.168.1.0")
    if not sourceMask:
        sourceMask_input = prompt("Source Network Subnet (Subnet Mask or CIDR, e.g., /24): ", "/24")
        sourceMask = get_subnet_mask(sourceMask_input)
        if not sourceMask:
            print("Invalid source subnet mask or CIDR notation.")
            return
    if not dstAddr:
        dstAddr = prompt("Destination Address: ", "192.168.2.0")
    if not dstMask:
        dstMask_input = prompt("Destination Network Subnet (Subnet Mask or CIDR, e.g., /24): ", "/24")
        dstMask = get_subnet_mask(dstMask_input)
        if not dstMask:
            print("Invalid destination subnet mask or CIDR notation.")
            return

    source_wildcard = '.'.join([str(255 - int(octet)) for octet in sourceMask.split('.')])
    dst_wildcard = '.'.join([str(255 - int(octet)) for octet in dstMask.split('.')])

    print("\n[orchid2]Generation: (Router Configurations)[/orchid2]\n")
    outputCiscoCode(f"ip access-list extended {listName}", "router")
    outputCiscoCode(f"   {aceNum} {rule} {protocol} {sourceAddr} {source_wildcard} {dstAddr} {dst_wildcard}", "router")
    outputCiscoCode(f"   exit", "router")

def autoOSPF(pid=None, networks=None):
    if not pid:
        pid = prompt("Process ID (PID): ", "1")
    if not networks:
        networks_input = prompt("List networks (comma or space-separated, e.g., 192.168.1.0,192.168.2.0): ", "192.168.1.0 192.168.2.0")
        networks = [net.strip() for net in networks_input.replace(',', ' ').split()]

    network_data = []
    for net in networks:
        net_mask_input = prompt(f"Enter subnet mask or CIDR for network {net}: ", "/24")
        net_mask = get_subnet_mask(net_mask_input)
        if not net_mask:
            print(f"Invalid subnet mask or CIDR notation for network {net}.")
            return
        wildcard_mask = '.'.join([str(255 - int(octet)) for octet in net_mask.split('.')])
        network_data.append((net, wildcard_mask))

    print("\n[orchid2]Generation: (Router Configurations)[/orchid2]\n")
    outputCiscoCode(f"router ospf {pid}", "router")
    for net, wildcard_mask in network_data:
        outputCiscoCode(f"   network {net} {wildcard_mask} area 0", "router")
    outputCiscoCode(f"   exit", "router")

def autoRIP(networks=None):
    if not networks:
        networks_input = prompt("List networks (comma or space-separated, e.g., 192.168.1.0,192.168.2.0): ", "192.168.1.0 192.168.2.0")
        networks = [net.strip() for net in networks_input.replace(',', ' ').split()]
    print("\n[orchid2]Generation: (Router Configurations)[/orchid2]\n")
    outputCiscoCode("router rip", "router")
    outputCiscoCode("   version 2", "router")
    for net in networks:
        outputCiscoCode(f"   network {net}", "router")
    outputCiscoCode("   exit", "router")

def autoSubnet(network=None, subnet=None):
    if not network:
        network = prompt("Any Address: ", "192.168.1.5")
    if not subnet:
        subnet_input = prompt("Network Subnet (Subnet Mask or CIDR, e.g., /24): ", "/24")
        subnet = get_subnet_mask(subnet_input)
        if not subnet:
            print("Invalid subnet mask or CIDR notation.")
            return
    network_info = get_network_info(network, subnet)
    if None in network_info:
        print("Invalid network address or subnet mask.")
        return
    print(f"[dodger_blue1]Network Address: [/dodger_blue1]{network_info[0]}")
    print(f"[dodger_blue1]Broadcast Address: [/dodger_blue1]{network_info[1]}")
    print(f"[dodger_blue1]First Available Address: [/dodger_blue1]{network_info[2]}")
    print(f"[dodger_blue1]Last Available Address: [/dodger_blue1]{network_info[3]}")
    print(f"[dodger_blue1]Address Range: [/dodger_blue1]{network_info[2]} - {network_info[3]}")

def autoAddress(network=None, subnet=None, address=None, routerInterface=None):
    if not network:
        network = prompt("Any Address: ", "192.168.1.0")
    if not subnet:
        subnet_input = prompt("Network Subnet (Subnet Mask or CIDR, e.g., /24): ", "/24")
        subnet = get_subnet_mask(subnet_input)
        if not subnet:
            print("Invalid subnet mask or CIDR notation.")
            return
    network_info = get_network_info(network, subnet)
    if None in network_info:
        print("Invalid network address or subnet mask.")
        return
    if not address:
        address_input = prompt("Address (first | last | specific IP): ", "first").lower()
        if address_input == "first":
            address = network_info[2]
        elif address_input == "last":
            address = network_info[3]
        else:
            address = address_input
            if not checkIP(address):
                print("Invalid IP address.")
                return
    if not routerInterface:
        routerInterface = prompt("Router Interface (e.g., GigabitEthernet0/0/0): ", "GigabitEthernet0/0/0").strip()
        if not routerInterface:
            routerInterface = "GigabitEthernet0/0/0"
    print("\n[orchid2]Generation: (Router Configurations)[/orchid2]\n")
    outputCiscoCode(f"interface {routerInterface}", "router")
    outputCiscoCode(f"   ip address {address} {subnet}", "router")
    outputCiscoCode(f"   no shutdown", "router")
    outputCiscoCode(f"   exit", "router")

def printMenu(menu):
    print("Menu:")
    for item in menu:
        print(item)
    return input("Choice: ")

def saveCONFS():
    router = "ROUTER CONFIGURATION:"
    switch = "SWITCH CONFIGURATION:"
    for i in routerConfs:
        router += "\n" + i
    for i in switchConfs:
        switch += "\n" + i
    if router != "ROUTER CONFIGURATION:" or switch != "SWITCH CONFIGURATION:":
        name = prompt("Filename: ", "configurations.txt")
        with open(name, "w") as f:
            if router != "ROUTER CONFIGURATION:":
                f.write(router + "\n")
            if switch != "SWITCH CONFIGURATION:":
                f.write(switch + "\n")
        print(f"Configurations saved to {name}")
    else:
        print("Nothing Recorded")

def main():
    print("""
_____________                                      
__  ____/__(_)__________________                   
_  /    __  /__  ___/  ___/  __ \                  
/ /___  _  / _(__  )/ /__ / /_/ /                  
\____/  /_/  /____/ \___/ \____/                   
                                                   
_________            ___________________     _____ 
__  ____/_____       ___  __ \__(_)__  /_______  /_
_  /    _  __ \________  /_/ /_  /__  /_  __ \  __/
/ /___  / /_/ //_____/  ____/_  / _  / / /_/ / /_  
\____/  \____/       /_/     /_/  /_/  \____/\__/

""")
    options = [
        "1 - Auto DHCP",
        "2 - Auto VLAN",
        "3 - Auto ACLs",
        "4 - Auto OSPF",
        "5 - Auto RIP",
        "6 - Auto Subnet Calculator",
        "7 - Auto Assign Addresses",
        "8 - Save Configurations",
        "9 - Exit"
    ]
    choice = printMenu(options)
    if choice == "1":
        autoDHCP()
    elif choice == "2":
        autoVLAN()
    elif choice == "3":
        c = printMenu(["1 - Standard ACL", "2 - Extended ACL"])
        if c == "1":
            autoStandardACL()
        elif c == "2":
            autoExtendedACL()
    elif choice == "4":
        autoOSPF()
    elif choice == "5":
        autoRIP()
    elif choice == "6":
        autoSubnet()
    elif choice == "7":
        autoAddress()
    elif choice == "8":
        saveCONFS()
    elif choice == "9":
        i = prompt("Are you sure? (yes/no): ", "yes")
        if i.lower() == "yes":
            sys.exit()
    else:
        i = prompt("Invalid choice. Would you like to exit? (yes/no): ", "no")
        if i.lower() == "yes":
            sys.exit()

if __name__ == "__main__":
    while True:
        main()
