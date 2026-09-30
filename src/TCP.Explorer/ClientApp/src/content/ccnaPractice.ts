export interface PracticeScenario {
  id: string;
  topic: string;
  title: string;
  evidence: string;
  question: string;
  choices: string[];
  answer: number;
  hint: string;
  explanation: string;
  next: string;
  explore?: { to: string; label: string };
}

/** Original study examples, not exam questions. Evidence is illustrative, not simulator output. */
export const ccnaPractice: PracticeScenario[] = [
  {
    id: 'subnet', topic: 'Network fundamentals', title: 'Find the subnet boundary',
    evidence: 'Host: 192.0.2.77/27\nMask: 255.255.255.224',
    question: 'Which network, broadcast address, and usable host range contain this host?',
    choices: ['Network .0; broadcast .255; hosts .1–.254', 'Network .64; broadcast .95; hosts .65–.94', 'Network .77; broadcast .108; hosts .78–.107'],
    answer: 1, hint: 'A /27 leaves five host bits. Find the block of 32 addresses containing 77.',
    explanation: 'The blocks begin at 0, 32, 64, 96, and so on. 77 falls in 64–95, so the network is 192.0.2.64 and broadcast is 192.0.2.95. Excluding those two addresses leaves 30 usable hosts, .65 through .94.',
    next: 'Without a calculator, find the network, broadcast, and host range for 192.0.2.142/28.',
    explore: { to: '/layers/network', label: 'Explore the network layer' }
  },
  {
    id: 'gateway', topic: 'Network fundamentals', title: 'Choose the next-hop MAC',
    evidence: 'Host A: 192.0.2.10/24\nGateway: 192.0.2.1\nDestination: 198.51.100.20\nARP cache: empty',
    question: 'For an ordinary routed connection, whose MAC address does Host A resolve first?',
    choices: ['The remote destination’s MAC', 'The local DNS server’s MAC', 'The default gateway’s MAC'],
    answer: 2, hint: 'Compare the destination with the local subnet. Ethernet delivers to a next hop on the local link.',
    explanation: 'The destination is off-subnet, so Host A uses ARP for 192.0.2.1. Its Ethernet frame targets the gateway’s MAC while its IP packet still targets 198.51.100.20. Routers replace link-layer headers at each hop; they do not carry the original Ethernet frame across the whole path.',
    next: 'Explain what changes when the destination is 192.0.2.20, then identify the ARP exchange in the ping experiment.',
    explore: { to: '/transmit?scenario=ping', label: 'Observe local ARP and ping' }
  },
  {
    id: 'ipv6', topic: 'Network fundamentals', title: 'Recognize an IPv6 address',
    evidence: 'Interface address: fe80::12ab:34ff:fe56:7890/64',
    question: 'What scope does this address have?',
    choices: ['Link-local; routers do not forward packets with this destination to another link', 'Global unicast; reachable across the Internet by default', 'Multicast; identifies every host on the link'],
    answer: 0, hint: 'Look at the leading fe80 prefix.',
    explanation: 'fe80::/10 identifies link-local unicast addresses. They support communication on one link, including neighbor discovery and routing-protocol exchanges. IPv6 uses Neighbor Discovery rather than IPv4 ARP.',
    next: 'Compare link-local, global unicast, unique local, multicast, and anycast addresses. Practice compressing and expanding IPv6 notation.'
  },
  {
    id: 'vlan', topic: 'Network access', title: 'Repair a missing VLAN',
    evidence: 'PC A — SW1 — trunk — SW2 — PC B\nBoth PCs: VLAN 20, same IPv4 /24\nVLAN 20 exists on both switches\nSW1 trunk allows: 10,20\nSW2 trunk allows: 10\nAll ports are up and forwarding',
    question: 'Which change restores VLAN 20 traffic across this trunk?',
    choices: ['Change both PCs’ default gateways', 'Add VLAN 20 to SW2’s trunk allowed list', 'Put each PC in a different subnet'],
    answer: 1, hint: 'Check whether VLAN 20 can cross both ends of the trunk.',
    explanation: 'The trunk must carry VLAN 20 on both ends. On SW2’s trunk interface, switchport trunk allowed vlan add 20 preserves VLAN 10 and adds VLAN 20. Verify with show interfaces trunk. Same-subnet traffic within a VLAN does not require a default gateway.',
    next: 'Explain access versus trunk ports, the native VLAN, and why communication between VLANs needs Layer 3 forwarding.',
    explore: { to: '/layers/link/headers', label: 'Inspect an 802.1Q header' }
  },
  {
    id: 'stp', topic: 'Network access', title: 'Elect the root bridge',
    evidence: 'Rapid PVST+, VLAN 10\nSW1: configured priority 32768, MAC 00:00:00:00:00:01\nSW2: configured priority 24576, MAC 00:00:00:00:00:02\nSW3: configured priority 32768, MAC 00:00:00:00:00:03',
    question: 'Which switch becomes the root bridge for VLAN 10?',
    choices: ['SW1, because it has the lowest MAC', 'SW3, because it has the highest MAC', 'SW2, because it has the lowest bridge ID'],
    answer: 2, hint: 'Compare priority before MAC address. The VLAN extension is the same for all three.',
    explanation: 'The lowest bridge ID wins. SW2 has the lowest priority, so its higher MAC does not matter. MAC address breaks a tie when priority values are equal. Non-root switches then choose root ports using their best path toward the root.',
    next: 'Draw a triangle of switches and predict root, designated, and alternate ports. Explain PortFast and why BPDU guard is useful on edge ports.'
  },
  {
    id: 'route', topic: 'IP connectivity', title: 'Read a forwarding decision',
    evidence: 'Installed IPv4 routes:\nS  10.0.0.0/8       [1/0] via 192.0.2.1\nO  10.20.0.0/16    [110/20] via 192.0.2.2\nS* 0.0.0.0/0        [1/0] via 192.0.2.254\nDestination: 10.20.30.40',
    question: 'Which next hop does the router use?',
    choices: ['192.0.2.2, using the /16 route', '192.0.2.1, because static routes have lower administrative distance', '192.0.2.254, using the default route'],
    answer: 0, hint: 'These routes are already installed. Compare matching prefix lengths.',
    explanation: 'The /16 is the longest matching prefix. Administrative distance helps select between route sources for the same prefix when building the routing table; it does not make an installed /8 beat an installed /16 during forwarding. The default route is used only when no more-specific route matches.',
    next: 'Add 10.20.30.0/24 via a third next hop and predict the result. Explain when a floating static route becomes active.',
    explore: { to: '/layers/network/code', label: 'Find routing in TCP.Core' }
  },
  {
    id: 'ospf', topic: 'IP connectivity', title: 'Find an OSPF mismatch',
    evidence: 'R1: 192.0.2.1/30, area 0, hello 10 s, dead 40 s\nR2: 192.0.2.2/30, area 1, hello 10 s, dead 40 s\nSame Ethernet link; interfaces up\nNo passive interfaces or authentication; unique router IDs',
    question: 'What prevents these routers from becoming OSPF neighbors on this link?',
    choices: ['Their interface addresses are different', 'Their areas differ', 'Their router IDs must be equal'],
    answer: 1, hint: 'Neighbors on one OSPF link must agree on the area.',
    explanation: 'Area 0 and area 1 do not match. Configure both link interfaces in the intended common area, then verify with show ip ospf interface and show ip ospf neighbor. Router IDs should be unique, and neighboring interfaces normally have different addresses in the same subnet.',
    next: 'List other adjacency checks: timers, subnet, authentication, passive interfaces, and network type. Explain DR/BDR elections on a broadcast network.'
  },
  {
    id: 'nat', topic: 'IP services', title: 'Distinguish NAT from PAT',
    evidence: 'Two internal clients:\n10.0.0.10:51500 → 203.0.113.5:40001\n10.0.0.11:51500 → 203.0.113.5:40002\nBoth connect to the same external HTTPS server',
    question: 'How can replies reach the correct internal client through one public address?',
    choices: ['The clients share one MAC address', 'DNS selects the internal client', 'PAT distinguishes translation entries using ports and protocol'],
    answer: 2, hint: 'The translated public IP is identical, but the translated ports differ.',
    explanation: 'Port Address Translation (NAT overload) tracks transport-layer ports and protocol along with addresses. The mappings let reply traffic return to the correct internal endpoint. A one-to-one static NAT mapping translates an address without needing many clients to share it.',
    next: 'Identify inside local and inside global addresses in this example, then compare static NAT, pool-based dynamic NAT, and PAT.'
  },
  {
    id: 'dhcp', topic: 'IP services', title: 'Reach a remote DHCP server',
    evidence: 'Client VLAN: 10.10.20.0/24\nGateway interface: 10.10.20.1\nDHCP server: 10.10.50.10 on another subnet\nRouting and server scope are correct; no relay configured\nClient broadcasts DHCPDISCOVER but receives no offer',
    question: 'What should you configure on the client-facing gateway interface?',
    choices: ['ip helper-address 10.10.50.10', 'A static ARP entry for every client', 'An extra default route on the client'],
    answer: 0, hint: 'A router does not ordinarily forward this client broadcast between subnets.',
    explanation: 'A DHCP relay receives the client broadcast and forwards the request to the server. On Cisco IOS, ip helper-address identifies that server. The relay identifies the client subnet so the server can select the appropriate scope.',
    next: 'Explain Discover, Offer, Request, and Acknowledge. Separately explain why a client with a valid IP address might still fail to resolve names.'
  },
  {
    id: 'acl', topic: 'Security fundamentals', title: 'Follow ACL processing order',
    evidence: 'Extended ACL, applied inbound on the client interface:\n10 deny tcp 10.10.20.0 0.0.0.255 any eq 22\n20 permit ip 10.10.20.0 0.0.0.255 any\nPacket: TCP 10.10.20.15:51000 → 198.51.100.20:22',
    question: 'What happens to this packet?',
    choices: ['Permitted because line 20 matches', 'Denied by line 10; processing stops at the first match', 'Permitted because the source port is not 22'],
    answer: 1, hint: 'Evaluate the entries top to bottom. Here, eq 22 follows the destination.',
    explanation: 'Line 10 matches the source subnet, TCP protocol, and destination port 22, so the packet is denied. Line 20 is never evaluated for it. ACLs use the first matching entry and have an implicit deny at the end; 0.0.0.255 is the wildcard for this /24.',
    next: 'Predict what happens to HTTPS from this client and to traffic from 10.10.30.15. Explain wildcard masks and inbound versus outbound placement.'
  },
  {
    id: 'wireless', topic: 'Security fundamentals / Network access', title: 'Diagnose a wireless join failure',
    evidence: 'Lab WLAN: SSID StudyLab, WPA2-Personal (PSK)\nClient sees StudyLab with strong signal\nClient has an old saved PSK\nAssociation/authentication fails before DHCP',
    question: 'Which action addresses the supplied evidence first?',
    choices: ['Change the DNS server', 'Add an IPv4 static route', 'Update the saved WPA2 pre-shared key'],
    answer: 2, hint: 'The failure occurs before the client can request an IP address.',
    explanation: 'The client must use the correct PSK to complete WPA2-Personal authentication and key establishment. DNS and IP routing do not fix a wireless authentication failure. Check SSID, security mode, credentials, and signal before investigating DHCP or higher layers.',
    next: 'Compare Personal and Enterprise authentication, WPA2 and WPA3, and nonoverlapping Wi-Fi channels. Practice reading a WLAN configuration screen.'
  },
  {
    id: 'api', topic: 'Automation and programmability', title: 'Read an API response',
    evidence: 'GET /api/interfaces\nHTTP 200 OK\n{ "interfaces": [{ "name": "Gi0/1", "enabled": true, "vlan": 20 }] }',
    question: 'Which interpretation is correct?',
    choices: ['GET reads data; interfaces is an array containing an object; enabled is a Boolean', 'GET deletes the interface; enabled is a string', 'The response creates VLAN 20 because every HTTP request changes configuration'],
    answer: 0, hint: 'Look at square brackets, braces, and the unquoted true value.',
    explanation: 'GET requests a representation of a resource. In JSON, brackets delimit arrays and braces delimit objects; true is a Boolean, 20 is a number, and "Gi0/1" is a string. A read response describes data rather than proving a configuration change.',
    next: 'Map CRUD to common HTTP methods, distinguish control and data planes, and explain the roles of Ansible, Terraform, and predictive versus generative AI.'
  }
];
