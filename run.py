try:
    import sys
    import ipaddress
    from rich import print
except:
    import os
    os.system("python3 -m pip install ipaddress")
    os.system("python3 -m pip install rich")
    import sys
    import ipaddress
    from rich import print

#Cisco Functions
cidrToSubnet = [
    {"prefix_length": "1", "subnet_mask": "128.0.0.0"},
    {"prefix_length": "2", "subnet_mask": "192.0.0.0"},
    {"prefix_length": "3", "subnet_mask": "224.0.0.0"},
    {"prefix_length": "4", "subnet_mask": "240.0.0.0"},
    {"prefix_length": "5", "subnet_mask": "248.0.0.0"},
    {"prefix_length": "6", "subnet_mask": "252.0.0.0"},
    {"prefix_length": "7", "subnet_mask": "254.0.0.0"},
    {"prefix_length": "8", "subnet_mask": "255.0.0.0"},
    {"prefix_length": "9", "subnet_mask": "255.128.0.0"},
    {"prefix_length": "10", "subnet_mask": "255.192.0.0"},
    {"prefix_length": "11", "subnet_mask": "255.224.0.0"},
    {"prefix_length": "12", "subnet_mask": "255.240.0.0"},
    {"prefix_length": "13", "subnet_mask": "255.248.0.0"},
    {"prefix_length": "14", "subnet_mask": "255.252.0.0"},
    {"prefix_length": "15", "subnet_mask": "255.254.0.0"},
    {"prefix_length": "16", "subnet_mask": "255.255.0.0"},
    {"prefix_length": "17", "subnet_mask": "255.255.128.0"},
    {"prefix_length": "18", "subnet_mask": "255.255.192.0"},
    {"prefix_length": "19", "subnet_mask": "255.255.224.0"},
    {"prefix_length": "20", "subnet_mask": "255.255.240.0"},
    {"prefix_length": "21", "subnet_mask": "255.255.248.0"},
    {"prefix_length": "22", "subnet_mask": "255.255.252.0"},
    {"prefix_length": "23", "subnet_mask": "255.255.254.0"},
    {"prefix_length": "24", "subnet_mask": "255.255.255.0"},
    {"prefix_length": "25", "subnet_mask": "255.255.255.128"},
    {"prefix_length": "26", "subnet_mask": "255.255.255.192"},
    {"prefix_length": "27", "subnet_mask": "255.255.255.224"},
    {"prefix_length": "28", "subnet_mask": "255.255.255.240"},
    {"prefix_length": "29", "subnet_mask": "255.255.255.248"},
    {"prefix_length": "30", "subnet_mask": "255.255.255.252"},
    {"prefix_length": "31", "subnet_mask": "255.255.255.254"},
    {"prefix_length": "32", "subnet_mask": "255.255.255.255"},
]

switchConfs = []
routerConfs = []

def CIDRToSubnetAndVerify(networkSubnet):
    if len(networkSubnet) <= 3:
        for i in cidrToSubnet:
            if networkSubnet.replace("/", "") == i["prefix_length"]:
                networkSubnet = i["subnet_mask"]
                return networkSubnet
                break
    else:
        return networkSubnet

def checkIP(ip):
    if ip.count('.') != 4:
        return False
    for i in ip.split("."):
        if int(i) < 255:
            return False
    return True

def get_network_info(ip_address, subnet_mask):
    ip_network = ipaddress.IPv4Network(f"{ip_address}/{subnet_mask}", strict=False)
    network_address = str(ip_network.network_address)
    broadcast_address = str(ip_network.broadcast_address)
    first_available_address = str(ip_network.network_address + 1)
    last_available_address = str(ip_network.broadcast_address - 1)
    return [network_address, broadcast_address, first_available_address, last_available_address]

def shortenInterfaces(interfaces):
    netInterfaces = []
    for i in interfaces:
        netInterfaces += [str(i).replace("ffe", "fastEthernet").replace("gie", "gigabitEthernet").replace("sse", "Serial")]
    return netInterfaces

def outputCiscoCode(code, device):
    global switchConfs, routerConfs
    colorChanges = [
        {
            "color": "magenta",
            "keyword": "ip"
        },
        {
            "color": "magenta",
            "keyword": "address"
        },
        {
            "color": "magenta",
            "keyword": "name"
        },
        {
            "color": "dodger_blue1",
            "keyword": "dhcp"
        },
        {
            "color": "dodger_blue1",
            "keyword": "encapsulation"
        },
        {
            "color": "cyan1",
            "keyword": "exclude-addresss"
        },
        {
            "color": "magenta",
            "keyword": "pool"
        },
        {
            "color": "magenta",
            "keyword": "dot1Q"
        },
        {
            "color": "magenta",
            "keyword": "access-list"
        },
        {
            "color": "magenta",
            "keyword": "router"
        },
        {
            "color": "magenta",
            "keyword": "access"
        },
        {
            "color": "magenta",
            "keyword": "trunk"
        },
        {
            "color": "magenta",
            "keyword": "no"
        },
        {
            "color": "cyan1",
            "keyword": "default-router"
        },
        {
            "color": "cyan1",
            "keyword": "dns-server"
        },
        {
            "color": "cyan1",
            "keyword": "domain-name"
        },
        {
            "color": "cyan1",
            "keyword": "network"
        },
        {
            "color": "cyan1",
            "keyword": "mode"
        },
        {
            "color": "cyan1",
            "keyword": "standard"
        },
        {
            "color": "cyan1",
            "keyword": "extended"
        },
        {
            "color": "cyan1",
            "keyword": "ospf"
        },
        {
            "color": "cyan1",
            "keyword": "rip"
        },
        {
            "color": "deep_pink2",
            "keyword": "exit"
        },
        {
            "color": "deep_pink2",
            "keyword": "deny"
        },
        {
            "color": "deep_pink2",
            "keyword": "shutdown"
        },
        {
            "color": "orange1",
            "keyword": "interface"
        },
        {
            "color": "orange1",
            "keyword": "tcp"
        },
        {
            "color": "orange1",
            "keyword": "udp"
        },
        {
            "color": "plum1",
            "keyword": "switchport"
        },
        {
            "color": "plum1",
            "keyword": "area"
        },
        {
            "color": "plum1",
            "keyword": "version"
        },
        {
            "color": "orange_red1",
            "keyword": "vlan"
        },
        {
            "color": "medium_spring_green",
            "keyword": "fastEthernet"
        },
        {
            "color": "medium_spring_green",
            "keyword": "gigabitEthernet"
        },
        {
            "color": "medium_spring_green",
            "keyword": "permit"
        },
    ]

    code = code.replace("fastEthernet", "fastEthernet ").replace("gigabitEthernet", "gigabitEthernet ") + " "
    code = code.replace("gigabitEthernet  ", "gigabitEthernet ")
    if device == "router":
        routerConfs += [code]
    elif device == "switch":
        switchConfs += [code]
    for i in colorChanges:
        code = code.replace(str(i["keyword"] + " "), "[bold "+ i["color"] + "]" + str(i["keyword"] + " ") + "[/bold "+ i["color"] + "]").replace(str(i["keyword"] + " ").lower(), "[bold "+ i["color"] + "]" + str(i["keyword"] + " ") + "[/bold "+ i["color"] + "]").replace(str(i["keyword"] + " ").upper(), "[bold "+ i["color"] + "]" + str(i["keyword"] + " ") + "[/bold "+ i["color"] + "]")
    print(code)

def autoDHCP(name, networkAddress, networkSubnet, networkDNSServer, domainName):
    if not name and not networkAddress and not networkSubnet and not networkDNSServer and not domainName:
        name = input("Name Of Pool: ")
        networkAddress = input("Network Address: ")
        networkSubnet = CIDRToSubnetAndVerify(input("Network Subnet (Or CIDR): "))
        networkDNSServer = input("DNS Server: ")
        domainName = input("Domain Name: ")

    if networkSubnet != False:
        print("")
        print("[orchid2]Generation: (Router Configurations)[/orchid2]")
        print("")
        outputCiscoCode("ip dhcp exclude-addresss " + get_network_info(networkAddress, networkSubnet)[3], "router")
        outputCiscoCode("ip dhcp pool " + name.replace(" ", "_"), "router")
        outputCiscoCode("   default-router " + get_network_info(networkAddress, networkSubnet)[3], "router")
        outputCiscoCode("   dns-server " + networkDNSServer, "router")
        outputCiscoCode("   domain-name " + domainName, "router")
        outputCiscoCode("   network " + get_network_info(networkAddress, networkSubnet)[2] + " " + networkSubnet, "router")
        outputCiscoCode("   exit", "router")

def autoVLAN(number, name, networkAddress, networkSubnet, routerInterface, switchPortsOnVLAN):
    if not number and not name and not networkAddress and not networkSubnet and not routerInterface and not switchPortsOnVLAN:
        number = input("VLAN Number: ")
        name = input("VLAN Name: ")
        networkAddress = input("Network Address: ")
        networkSubnet = CIDRToSubnetAndVerify(input("Network Subnet (Or CIDR): "))
        networkAddress = get_network_info(networkAddress, networkSubnet)[3]
        routerInterface = shortenInterfaces([input("Router Interface (gigabitEthernet 0/0/0): ")])[0]
        if routerInterface == "":
            routerInterface = "gigabitEthernet 0/0/0"
        switchPortsOnVLAN = shortenInterfaces(input("Switch Ports on VLAN (fastEthernet 0/4, fastEthernet 0/5): ").replace(" ", "").split(","))

    if networkSubnet != False:
        print("")
        print("[orchid2]Generation: (Router Configurations)[/orchid2]")
        print("")
        outputCiscoCode("interface " + routerInterface + "." + str(number), "router")
        outputCiscoCode("   encapsulation dot1Q " + str(number), "router")
        outputCiscoCode("   ip address " + networkAddress + " " + networkSubnet, "router")
        outputCiscoCode("   exit", "router")
        print("")
        print("[orchid2]Generation: (Switch Configurations)[/orchid2]")
        print("")
        outputCiscoCode("vlan " + str(number), "switch")
        outputCiscoCode("   name " + name.replace(" ", "_"), "switch")
        outputCiscoCode("   exit", "switch")
        for i in switchPortsOnVLAN:
            outputCiscoCode("interface " + str(i), "switch")
            outputCiscoCode("   switchport mode access", "switch")
            outputCiscoCode("   switchport access vlan " + str(number), "switch")
            outputCiscoCode("   exit", "switch")
        outputCiscoCode("interface " + routerInterface, "switch")
        outputCiscoCode("   switchport mode trunk", "switch")
        outputCiscoCode("   exit", "switch")

def autoStandardACL(listName, aceNum, rule, sourceAddr, sourceMask):
    if not listName and not aceNum and not rule and not sourceAddr and not sourceMask:
        listName = input("List Name: ")
        aceNum = input("ACE number: ")
        rule = input("ACE rule (deny | permit| remark text): ")
        sourceAddr = input("Source Address: ")
        sourceMask = CIDRToSubnetAndVerify(input("Source Network Subnet (Or CIDR): "))

    sourceAddr = get_network_info(sourceAddr, sourceMask)[0]

    maskList = sourceMask.split(".")
    sourceMask = str(255 - int(maskList[0])) + "." + str(255 - int(maskList[1])) + "."  + str(255 - int(maskList[2])) + "." + str(255 - int(maskList[3]))

    print("")
    print("[orchid2]Generation: (Router Configurations)[/orchid2]")
    print("")
    outputCiscoCode("ip access-list standard " + listName, "router")
    outputCiscoCode("   " + aceNum + " " + rule + " " + sourceAddr + " " + sourceMask, "router")
    outputCiscoCode("   exit", "router")

def autoExtendedACL(listName, aceNum, rule, sourceAddr, sourceMask, dstAddr, dstMask):
    if not listName and not aceNum and not rule and not sourceAddr and not sourceMask and not dstMask and not dstAddr:
        listName = input("List Name: ")
        aceNum = input("ACE number: ")
        rule = input("ACE rule (deny | permit| remark text): ")
        protocol = input("Protocol (TCP | UDP): ")
        sourceAddr = input("Source Address: ")
        sourceMask = CIDRToSubnetAndVerify(input("Source Network Subnet (Or CIDR): "))
        dstAddr = input("Destination Address: ")
        dstMask = CIDRToSubnetAndVerify(input("Destination Network Subnet (Or CIDR): "))

    sourceAddr = get_network_info(sourceAddr, sourceMask)[0]
    dstAddr = get_network_info(sourceAddr, sourceMask)[0]

    maskList = sourceMask.split(".")
    sourceMask = str(255 - int(maskList[0])) + "." + str(255 - int(maskList[1])) + "."  + str(255 - int(maskList[2])) + "." + str(255 - int(maskList[3]))

    maskList = dstMask.split(".")
    dstMask = str(255 - int(maskList[0])) + "." + str(255 - int(maskList[1])) + "."  + str(255 - int(maskList[2])) + "." + str(255 - int(maskList[3]))

    print("")
    print("[orchid2]Generation: (Router Configurations)[/orchid2]")
    print("")
    outputCiscoCode("ip access-list extended " + listName, "router")
    outputCiscoCode("   " + aceNum + " " + rule + " " + protocol + " " + sourceAddr + " " + sourceMask + " " + dstAddr + " " + dstMask, "router")
    outputCiscoCode("   exit", "router")

def autoOSPF(pid, networks):
    if not pid and not networks:
        pid = input("PID: ")
        networks = input("List networks (192.168.1.1, 192.168.1.2): ").replace(" ", "").split(",")
    
    print("")
    print("[orchid2]Generation: (Router Configurations)[/orchid2]")
    print("")
    outputCiscoCode("router ospf " + pid, "router")
    for i in networks:
        outputCiscoCode("   network " + i + " area 0", "router")
    outputCiscoCode("   exit", "router")

def autoRIP(networks):
    if not networks:
        networks = input("List networks (192.168.1.1, 192.168.1.2): ").replace(" ", "").split(",")
    print("")
    print("[orchid2]Generation: (Router Configurations)[/orchid2]")
    print("")
    outputCiscoCode("router rip", "router")
    outputCiscoCode("   version 2", "router")
    for i in networks:
        outputCiscoCode("   network " + i, "router")
    outputCiscoCode("   exit", "router")

def autoSubnet(network,subnet):
    if not network and not subnet:
        network = input("Any Address: ")
        subnet = CIDRToSubnetAndVerify(input("Network Subnet (Or CIDR): "))
    
    print("[dodger_blue1]Network Address: [/dodger_blue1]" + get_network_info(network, subnet)[0])
    print("[dodger_blue1]Brodcast Address: [/dodger_blue1]" + get_network_info(network, subnet)[1])
    print("[dodger_blue1]First Available Address: [/dodger_blue1]" + get_network_info(network, subnet)[2])
    print("[dodger_blue1]Last Available Address: [/dodger_blue1]" + get_network_info(network, subnet)[3])
    print("[dodger_blue1]Address Range: [/dodger_blue1]" + get_network_info(network, subnet)[2] + " - " + get_network_info(network, subnet)[3])

def autoAddress(network, subnet, address, routerInterface):
    if not network and not subnet and not address and not routerInterface:
        network = input("Any Address: ")
        subnet = CIDRToSubnetAndVerify(input("Network Subnet (Or CIDR): "))
        address = input("Address (First | Last | IP): ")
        if address.lower() == "first":
            address = get_network_info(network, subnet)[2]
        elif address.lower() == "last":
            address = get_network_info(network, subnet)[3]
        routerInterface = shortenInterfaces([input("Router Interface (gigabitEthernet 0/0/0): ")])[0]
        if routerInterface == "":
            routerInterface = "gigabitEthernet 0/0/0"
        
    outputCiscoCode("interface " + routerInterface, "router")
    outputCiscoCode("   ip address " + address, "router")
    outputCiscoCode("   no shutdown", "router")
    outputCiscoCode("   exit", "router")

#Program Functions
def printMenu(menu):
    print("Menu: ")
    mid_point = (len(menu) + 1) // 2
    left_col = menu[:mid_point]
    right_col = menu[mid_point:]
    for i in range(max(len(left_col), len(right_col))):
        if i < len(left_col):
            print(left_col[i].ljust(20), end="")
        else:
            print(" "*20, end="")
        if i < len(right_col):
            print(right_col[i].ljust(20))
        else:
            print()
    return input("Choice: ")

def saveCONFS():
    router = "ROUTER:"
    switch = "SWITCH:"
    for i in routerConfs:
        router += "\n" + i
    for i in switchConfs:
        switch += "\n" + i
    if router != "ROUTER:" and switch != "SWITCH:":
        name = input("Filename: ")
        with open(name, "a") as f:
            f.write(router + switch)
    elif router != "ROUTER:":
        name = input("Filename: ")
        with open(name, "a") as f:
            f.write(router)
    elif switch != "SWITCH:":
        name = input("Filename: ")
        with open(name, "a") as f:
            f.write(switch)
    else:
        print("Nothing Recorded")

def main():
    print("   ___ _                   _         _          ___ _ _       _   ")
    print("  / __(_)___  ___ ___     /_\  _   _| |_ ___   / _ (_) | ___ | |_ ")
    print(" / /  | / __|/ __/ _ \   //_\\| | | | __/ _ \ / /_)/ | |/ _ \| __|")
    print("/ /___| \__ \ (_| (_) | /  _  \ |_| | || (_) / ___/| | | (_) | |_ ")
    print("\____/|_|___/\___\___/  \_/ \_/\__,_|\__\___/\/    |_|_|\___/ \__|")
    print("")
    options = ["1 - Auto DHCP", "2 - Auto VLAN", "3 - AUTO ACLs", "4 - AUTO OSPF", "5 - AUTO RIP", "6 - AUTO SUBNET", "7 - AUTO ASSIGN ADDRESSES", "8 - SAVE CONFS (BETA)", "9 - EXIT"]
    choice = printMenu(options)
    if choice == "1":
        autoDHCP(False, False, False, False, False)
    elif choice == "2":
        autoVLAN(False, False, False, False, False, False)
    elif choice == "3":
        c = printMenu(["1 - Standard ACL", "2 - Extended ACL"])
        if c == "1":
            autoStandardACL(False, False, False, False, False)
        elif c == "2":
            autoExtendedACL(False, False, False, False, False, False, False)
    elif choice == "4":
        autoOSPF(False, False)
    elif choice == "5":
        autoRIP(False)
    elif choice == "6":
        autoSubnet(False, False)
    elif choice == "7":
        autoAddress(False, False, False, False)
    elif choice == "8":
        saveCONFS()
    elif choice == "9":
        i = input("Are you sure? (yes/no): ")
        if i == "yes":
            sys.exit()
        else:
            main()
    else:
        i = input("Would you like to exit? (yes/no): ")
        if i == "yes":
            sys.exit()
        else:
            main()
while True:
    main()
    c = input("Need anything else? (y/n)")
    if c == "y":
        main()
    else:
        break