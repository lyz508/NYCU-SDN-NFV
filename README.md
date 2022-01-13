# SDN-NFV
## Learning Bridge
- Developing with ONOS Java API to control flow and add flow rules.
- Forwarding Packets.
- Install Flow Rule.

## Unicast DHCP
- decide path via input packet
- implementation of unicast DHCP

## Proxy ARP
- Receive ARP request and packet out to find target MAC HW address at first.
- Recording IP and MAC.
- If an ARP request can find corresponding target MAC HW address.
  - Directly emit ARP_REPLY packet to sender.
- Decreasing pakcets on LAN.

## Vlan-Based Segment Routing
- Connect different subnets with Vlan ID
- Partition original network to subnets
- Find SP and forward packets
- Use configuration file for indicating edge switch