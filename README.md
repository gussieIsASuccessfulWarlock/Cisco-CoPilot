# Cisco-CoPilot: README

## Overview

**Cisco-CoPilot** is a Python-based tool for generating configurations for Cisco network devices, including routers and switches. It streamlines network administration tasks such as setting up DHCP, VLANs, ACLs, routing protocols, and subnet calculations.

This tool provides an interactive CLI interface where users can input parameters or use default examples to generate accurate Cisco configurations. It is designed for network engineers, administrators, and students to simplify and automate network management.

## Features

- **Auto DHCP**: Generate DHCP configurations with options for pool name, network, DNS server, and domain name.
- **Auto VLAN**: Automate VLAN creation and assignment of switch ports.
- **ACL Generation**:
  - Standard Access Control Lists (ACLs)
  - Extended Access Control Lists (ACLs)
- **Routing Protocols**:
  - OSPF (Open Shortest Path First)
  - RIP (Routing Information Protocol)
- **Subnet Calculator**: Calculate network, broadcast, and available address ranges.
- **Address Assignment**: Assign specific IP addresses to interfaces with subnet masks.
- **Configuration Saving**: Save generated configurations for both routers and switches to a file.

## Requirements

- Python 3.6 or higher
- The following Python libraries:
  - `rich`
  - `ipaddress`
- To install the required libraries, run:
  ```bash
  pip install -r requirements.txt
  ```

## Usage

1. Clone the repository:
   ```bash
   git clone https://github.com/gussieIsASuccessfulWarlock/Cisco-CoPilot.git
   cd Cisco-CoPilot
   ```

2. Run the script:
   ```bash
   python run.py
   ```

3. Select options from the main menu:
   - `Auto DHCP`: Configure DHCP settings.
   - `Auto VLAN`: Set up VLANs on switches.
   - `Auto ACLs`: Generate Standard or Extended ACLs.
   - `Auto OSPF`: Configure OSPF with specified networks.
   - `Auto RIP`: Configure RIP for routing.
   - `Auto Subnet Calculator`: Calculate network address details.
   - `Auto Assign Addresses`: Assign IP addresses to router interfaces.
   - `Save Configurations`: Save generated configurations to a file.


## Example Usage

### Auto DHCP
Input pool name, network details, DNS, and domain to generate a DHCP configuration.

```text
Name Of Pool: ExamplePool
Network Address: 192.168.1.0
Network Subnet (Subnet Mask or CIDR, e.g., /24): /24
DNS Server: 8.8.8.8
Domain Name: example.local
```

**Generated Output**:
```plaintext
ip dhcp excluded-address 192.168.1.1 192.168.1.254
ip dhcp pool ExamplePool
  network 192.168.1.0 255.255.255.0
  default-router 192.168.1.1
  dns-server 8.8.8.8
  domain-name example.local
  exit
```


## Saving Configurations

To save generated configurations, choose the "Save Configurations" option and provide a filename (e.g., `configurations.txt`). The file will contain both router and switch configurations.

## License

This project is licensed under the Apache-2.0 License. See the `LICENSE` file for details.

Developed by [gussieIsASuccessfulWarlock](https://github.com/gussieIsASuccessfulWarlock).
