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

def CIDRToSubnetAndVerify(networkSubnet):
    if len(networkSubnet) <= 3:
        for i in cidrToSubnet:
            if networkSubnet.replace("/", "") == i["prefix_length"]:
                networkSubnet = i["subnet_mask"]
                return networkSubnet
                break
    elif networkAddress.count('.') != 4:
        print("Subnet Doesn't Look Correct")
        return False
        sys.exit()
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

def autoDHCP(name, networkAddress, networkSubnet, networkDNSServer, domainName):
    if not name and not networkAddress and not networkSubnet and not networkDNSServer and not domainName:
        name = input("Name Of Pool: ")
        networkAddress = input("Network Address: ")
        networkSubnet = CIDRToSubnetAndVerify(input("Network Subnet (Or CIDR): "))
        networkDNSServer = input("DNS Server: ")
        domainName = input("Domain Name: ")

    if networkSubnet != False:
        print("")
        print("Generation: (Router Configurations)")
        print("")
        print("ip dhcp pool " + name.replace(" ", "_"))
        print("default-router " + get_network_info(networkAddress, networkSubnet)[3])
        print("dns-server " + networkDNSServer)
        print("domain-name " + domainName)
        print("network " + get_network_info(networkAddress, networkSubnet)[2] + " " + networkSubnet)

def autoVLAN(number, name, networkAddress, networkSubnet, routerInterface, switchPortsOnVLAN):
    if not number and not name and not networkAddress and not networkSubnet and not routerInterface and not switchPortsOnVLAN:
        number = input("VLAN Number: ")
        name = input("VLAN Name: ")
        networkAddress = input("Network Address: ")
        networkSubnet = CIDRToSubnetAndVerify(input("Network Subnet (Or CIDR): "))
        networkAddress = get_network_info(networkAddress, networkSubnet)[3]
        routerInterface = input("Router Interface (gigabitEthernet 0/0/0): ")
        switchPortsOnVLAN = input("Switch Ports on VLAN (fastEthernet 0/4, fastEthernet 0/5): ").replace(" ", "").split(",")

    if networkSubnet != False:
        print("")
        print("Generation: (Router Configurations)")
        print("")
        print("interface " + routerInterface + "." + str(number))
        print("encapsulation dot1Q " + str(number))
        print("ip address " + networkAddress + " " + networkSubnet)
        print("")
        print("Generation: (Switch Configurations)")
        print("")
        print("vlan " + str(number))
        print("name " + name.replace(" ", "_"))
        print("exit")
        for i in switchPortsOnVLAN:
            print("interface " + str(i).replace("ffe", "fastEthernet"))
            print("switchport mode access")
            print("switchport access vlan " + str(number))
            print("exit")
        print("interface " + routerInterface)
        print("switchport mode trunk")

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
    print("Generation: (Router Configurations)")
    print("")
    print("ip access-list standard " + listName)
    print("ip access-list " + aceNum + " " + rule + " " + sourceAddr + " " + sourceMask)
    print("exit")

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
    print("Generation: (Router Configurations)")
    print("")
    print("ip access-list extended " + listName)
    print("ip access-list " + aceNum + " " + rule + " " + protocol + " " + sourceAddr + " " + sourceMask + " " + dstAddr + " " + dstMask)
    print("exit")

def autoOSPF(pid, networks):
    if not pid and not networks:
        pid = input("PID: ")
        networks = input("List networks (192.168.1.1, 192.168.1.2): ").replace(" ", "").split(",")
    
    print("")
    print("Generation: (Router Configurations)")
    print("")
    print("router ospf " + pid)
    for i in networks:
        print("network " + i + " area 0")
    print("exit")

def autoRIP(networks):
    if not networks:
        networks = input("List networks (192.168.1.1, 192.168.1.2): ").replace(" ", "").split(",")
    print("")
    print("Generation: (Router Configurations)")
    print("")
    print("router rip")
    print("version 2")
    for i in networks:
        print("network " + i)
    print("exit")

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

def main():
    print("   ___ _                   _         _          ___ _ _       _   ")
    print("  / __(_)___  ___ ___     /_\  _   _| |_ ___   / _ (_) | ___ | |_ ")
    print(" / /  | / __|/ __/ _ \   //_\\| | | | __/ _ \ / /_)/ | |/ _ \| __|")
    print("/ /___| \__ \ (_| (_) | /  _  \ |_| | || (_) / ___/| | | (_) | |_ ")
    print("\____/|_|___/\___\___/  \_/ \_/\__,_|\__\___/\/    |_|_|\___/ \__|")
    print("")
    options = ["1 - Auto DHCP", "2 - Auto VLAN", "3 - AUTO ACLs", "4 - AUTO OSPF", "5 - AUTO RIP", "9 - EXIT"]
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
    elif choice == "9":
        sys.exit()
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