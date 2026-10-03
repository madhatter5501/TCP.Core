export interface Checkpoint {
  question: string;
  evidence: string;
  choices: string[];
  answer: number;
  explanation: string;
}

export interface PracticeLesson {
  goal: string;
  reasoning: string[];
  trap: string;
  checkpoints: Checkpoint[];
  lab: { task: string; commands: string; verify: string[] };
}

/** Each lesson adds transfer questions and an external lab to the foundation scenario. */
export const ccnaLessons: Record<string, PracticeLesson> = {
  subnet: {
    goal: 'Calculate address boundaries, distinguish usable hosts from total addresses, and allocate nonoverlapping VLSM subnets.',
    reasoning: [
      'IPv4 has 32 bits. /27 fixes 27 network bits and leaves 5 host bits: 2^5 = 32 total addresses. The mask’s last octet is 224; 256 − 224 gives the same block size.',
      'Round the last octet down to a multiple of 32: floor(77 / 32) × 32 = 64. The next block starts at 96, so the current broadcast is 95.',
      'The network and broadcast cannot be ordinary host addresses here. Count 32 − 2 = 30 usable hosts. A gateway consumes one of those usable addresses.',
      'For VLSM, allocate the largest requirement first on a valid boundary. Do not subtract two blindly for every prefix: /31 point-to-point links and /32 host routes have different uses.'
    ],
    trap: 'The host address is not the subnet start. A /27 is not a /24, and a subnet cannot begin at an arbitrary host number.',
    checkpoints: [
      { question: 'Solve the follow-up: what contains 192.0.2.142/28?', evidence: 'Prefix: /28\nLast octet: 142', choices: ['Network .128, broadcast .143, hosts .129–.142', 'Network .140, broadcast .155, hosts .141–.154', 'Network .128, broadcast .144, hosts .129–.143'], answer: 0, explanation: '/28 has a block size of 16. 142 is in 128–143. It is the last usable host; .143 is broadcast. The next subnet starts at .144.' },
      { question: 'Which VLSM plan fits 50, 25, and 10 ordinary host addresses without overlap?', evidence: 'Available: 192.0.2.0/24\nRequirements include gateway addresses.', choices: ['.0/27, .32/27, .64/28', '.0/26, .32/27, .64/28', '.0/26, .64/27, .96/28'], answer: 2, explanation: '50 hosts need /26 (62 usable); 25 need /27 (30); 10 need /28 (14). The valid ranges are .0–.63, .64–.95, and .96–.111. A /27 cannot fit 50; .32/27 overlaps .0/26.' }
    ],
    lab: { task: 'In Packet Tracer, connect two PCs through a switch. Configure .77/27 and .94/27, then change the second PC to .97/27 with no gateway. Predict each ping result before testing.', commands: 'PC command prompt:\nipconfig\nping 192.0.2.94\n\nAfter changing PC B to .97/27:\nping 192.0.2.97', verify: ['The first pair shares .64/27 and can communicate through the switch.', '.97 is a usable host in .96/27, a different subnet from .77/27. The .96 network address itself is not a host address. The second test needs Layer 3 forwarding and valid gateways; a switch alone cannot route between the subnets.', 'Check the configured masks before concluding that the cable or switch is broken.'] }
  },
  gateway: {
    goal: 'Trace both directions of a routed packet and separate end-to-end IP addressing from per-link Ethernet addressing.',
    reasoning: [
      'The host applies its subnet mask to its own and the destination address. A remote destination uses an applicable route, usually the default gateway.',
      'ARP resolves the next-hop IPv4 address on the local link. It does not ask the remote host for a MAC across routers.',
      'The router removes the incoming Ethernet header, decrements IPv4 TTL, updates the header checksum, looks up a route, and builds a frame for the next link.',
      'Without NAT, source and destination IPs remain end to end. Successful delivery also needs a return route and permits in both directions.'
    ],
    trap: 'A successful ARP exchange only proves local neighbor resolution. It does not prove the remote host is reachable or that the return path exists.',
    checkpoints: [
      { question: 'What leaves a router toward the destination LAN?', evidence: 'A 192.0.2.10 → R1 → B 198.51.100.20\nR1 directly connects both LANs. No NAT.\nR1 has resolved B’s MAC.', choices: ['IP destination becomes R1; Ethernet destination stays A', 'IP destination stays B; Ethernet destination is B’s MAC', 'Both destinations are always the original gateway'], answer: 1, explanation: 'R1 constructs a new Ethernet frame for B on the directly connected destination LAN. The IP destination remains B. R1’s outgoing interface supplies the Ethernet source MAC.' },
      { question: 'What happens to an IPv4 packet arriving with TTL 1?', evidence: 'R1 receives a packet that needs forwarding.\nTTL on arrival: 1', choices: ['R1 forwards it with TTL 0', 'R1 resets TTL to 64', 'R1 discards it and normally sends ICMP Time Exceeded'], answer: 2, explanation: 'Forwarding would expire the TTL, so R1 discards the packet. Normally it returns ICMP Time Exceeded, subject to rules and filtering. TTL limits loops; it is not a reliable delivery guarantee.' }
    ],
    lab: { task: 'Build two LANs joined by one router. Give both hosts the correct masks and gateways. Then remove B’s gateway and explain why resolving A’s gateway is insufficient.', commands: 'Router:\nshow ip interface brief\nshow ip route\nshow ip arp\n\nPC A:\nping 198.51.100.20\ntracert 198.51.100.20', verify: ['Both router LAN interfaces should be up/up with connected routes.', 'Simulation mode should show different Ethernet headers on the two links.', 'With B’s gateway removed, a remote ping can fail because B has no return path.'] }
  },
  ipv6: {
    goal: 'Recognize address scope, expand notation accurately, and understand neighbor discovery and IPv6 next hops.',
    reasoning: [
      'An IPv6 address has 128 bits, written as eight 16-bit hexadecimal groups. Leading zeros may be omitted within a group; :: may replace one contiguous run of zero groups.',
      'fe80::/10 is link-local, fc00::/7 is unique local, and ff00::/8 is multicast. Global unicast addresses are commonly drawn from 2000::/3.',
      'IPv6 has no broadcast address. ICMPv6 Neighbor Discovery uses multicast to discover neighbors and routers; disabling all ICMPv6 can break basic operation.',
      'A link-local next hop requires an interface context because the same link-local address can appear on separate links. Address scope and the interface prefix length are different concepts.'
    ],
    trap: 'A global address does not automatically guarantee Internet reachability. Routes, policies, and upstream connectivity still matter. The /64 on an interface does not change fe80’s link-local scope.',
    checkpoints: [
      { question: 'Expand 2001:db8:10::5 into eight groups.', evidence: '2001:db8:10::5', choices: ['2001:0db8:0010:0000:0000:0000:0000:0005', '2001:0db8:0010:0000:0000:0000:0005:0000', '2001:0db8:0010:0000:0000:0005'], answer: 0, explanation: 'Four groups are explicitly present, so :: contributes four zero groups. Expanding must preserve the final group’s position and produce exactly eight groups.' },
      { question: 'Why specify an exit interface with this static default route?', evidence: 'ipv6 route ::/0 GigabitEthernet0/0 fe80::1', choices: ['It converts the next hop into a global address', 'It identifies which link contains the link-local next hop', 'It enables IPv4 ARP for fe80::1'], answer: 1, explanation: 'fe80::1 is only meaningful in the context of a link. The interface disambiguates that next hop; IPv6 uses Neighbor Discovery, not IPv4 ARP.' }
    ],
    lab: { task: 'Enable IPv6 routing on a lab router, address two LANs using 2001:db8:10::/64 and 2001:db8:20::/64, and test both local and routed communication.', commands: 'Router global configuration:\nipv6 unicast-routing\ninterface GigabitEthernet0/0\n ipv6 address 2001:db8:10::1/64\n no shutdown\ninterface GigabitEthernet0/1\n ipv6 address 2001:db8:20::1/64\n no shutdown\n\nVerification:\nshow ipv6 interface brief\nshow ipv6 route\nshow ipv6 neighbors', verify: ['Connected IPv6 routes should appear for both LANs.', 'Hosts need IPv6 addresses and a default router for remote communication.', 'Use the neighbor table to distinguish next-hop discovery failures from missing routes.'] }
  },
  vlan: {
    goal: 'Troubleshoot VLAN traffic by separating access membership, trunk transport, spanning tree, and inter-VLAN routing.',
    reasoning: [
      'An access port puts ordinary untagged client traffic into one data VLAN. VLANs define separate Layer 2 broadcast domains.',
      'A trunk carries multiple VLANs using 802.1Q tags; the native VLAN is normally untagged unless native tagging is configured. An allowed list restricts which VLANs can cross.',
      'A VLAN must exist, be allowed, and be active and forwarding on the path. An up/up interface alone does not prove all three.',
      'Only after the Layer 2 path works should you investigate a router subinterface or switch virtual interface for inter-VLAN traffic.'
    ],
    trap: 'Replacing an allowed list with vlan 20 can remove existing VLANs. Use add when preserving the current list. Changing a gateway cannot fix a blocked same-VLAN trunk path.',
    checkpoints: [
      { question: 'Which command adds VLAN 20 without dropping VLAN 10?', evidence: 'SW2 Gi0/1 is already a trunk.\nCurrent allowed VLANs: 10', choices: ['switchport trunk allowed vlan 20', 'switchport access vlan 20', 'switchport trunk allowed vlan add 20'], answer: 2, explanation: 'add extends the allowed list. Without add, the command replaces the list with only VLAN 20. Setting an access VLAN does not repair a trunk allowed list.' },
      { question: 'VLAN 20 now crosses the trunk. Why can VLAN 20 hosts still not reach VLAN 30?', evidence: 'Each VLAN works internally.\nOnly Layer 2 switches connect the VLANs.\nNo router or Layer 3 switch is configured.', choices: ['They need a Layer 3 gateway and routing between VLANs', 'They need the same native VLAN on every access port', 'The trunk must remove VLAN tags from all frames'], answer: 0, explanation: 'A trunk transports separate VLANs; it does not route between them. Configure a router-on-a-stick or Layer 3 switch with gateways and suitable host addressing.' }
    ],
    lab: { task: 'Build the supplied two-switch topology with both PCs in VLAN 20. Remove VLAN 20 from one trunk end, observe the failure, then repair only that end. Interface names depend on your chosen switch.', commands: 'Inspect:\nshow vlan brief\nshow interfaces trunk\nshow spanning-tree vlan 20\nshow mac address-table dynamic vlan 20\n\nRepair on SW2 trunk interface:\ninterface GigabitEthernet0/1\n switchport trunk allowed vlan add 20', verify: ['VLAN 20 should appear in the allowed, active, and forwarding sections on both trunk ends.', 'MAC addresses should be learned on the appropriate access and trunk ports after traffic.', 'Same-VLAN ping should recover without changing either host’s default gateway.'] }
  },
  stp: {
    goal: 'Determine the root bridge and port roles from priorities, path costs, and tie breakers rather than guessing from the diagram.',
    reasoning: [
      'First elect the lowest bridge ID for this VLAN. Compare priority including the VLAN extension, then MAC address. Lower wins.',
      'Each non-root switch chooses one root port with the lowest total path cost to the root. Equal costs require tie breakers such as the sending bridge ID and port ID.',
      'Each segment gets a designated port advertising the best path to the root. Redundant alternatives discard traffic to prevent loops.',
      'PortFast lets an edge port move to forwarding quickly. BPDU guard protects an expected edge connection by disabling the port when a BPDU arrives; PortFast does not turn off spanning tree.'
    ],
    trap: 'Elect the root before assigning ports. A switch’s lowest MAC cannot defeat another switch’s lower priority. Do not apply edge-port assumptions to a switch-to-switch link.',
    checkpoints: [
      { question: 'Which port on SW3 is the root port?', evidence: 'Root: SW1\nSW3 → SW1: cost 4\nSW3 → SW2: cost 4; SW2 → SW1: cost 4', choices: ['SW3’s port toward SW2', 'SW3’s direct port toward SW1', 'Both ports are root ports'], answer: 1, explanation: 'The direct path costs 4; the path through SW2 costs 8. SW3 chooses its direct link to SW1. One non-root switch has one root port per spanning-tree instance.' },
      { question: 'Which end of the SW2–SW3 link becomes designated?', evidence: 'Both SW2 and SW3 have root path cost 4.\nSW2 bridge ID is lower than SW3 bridge ID.\nNo other ties exist.', choices: ['SW3, because it has the higher bridge ID', 'Both must discard', 'SW2; SW3’s redundant port is alternate/discarding'], answer: 2, explanation: 'On that segment the equal root path costs are broken by the bridge ID. SW2 wins designated; SW3’s link to SW2 is alternate because its direct root path is better.' }
    ],
    lab: { task: 'Connect three switches in a triangle in VLAN 10. Choose one root using a lower priority, observe the redundant port, then disconnect the root’s direct link to one non-root switch.', commands: 'On intended root, global configuration:\nspanning-tree vlan 10 priority 24576\n\nOn every switch:\nshow spanning-tree vlan 10', verify: ['All switches should identify the same root bridge.', 'Record port role, state, and path cost before changing the topology.', 'After failure, an alternate path can forward; a cable being up does not mean its port was forwarding before the failure.'] }
  },
  route: {
    goal: 'Separate route installation from packet forwarding and account for recursive next hops, defaults, and floating static routes.',
    reasoning: [
      'Read the destination prefix, route source, next hop, and [administrative distance/metric]. A smaller distance expresses preferred route source for the same prefix.',
      'For an actual packet, compare matching installed prefixes first. /24 beats /16; /16 beats /8; a /0 matches everything but loses to a more-specific match.',
      'Do not compare metrics from unrelated routing protocols as if they used a universal scale. OSPF cost and another protocol’s metric mean different things.',
      'A next-hop address must be reachable through routing resolution. A floating static route has a deliberately higher administrative distance and can replace a withdrawn primary route for the same prefix.'
    ],
    trap: 'An installed route’s administrative distance does not override longest prefix match. A default route cannot repair a missing return route on another device.',
    checkpoints: [
      { question: 'Which installed route forwards 10.20.30.40 now?', evidence: 'S 10.0.0.0/8 via 192.0.2.1\nO 10.20.0.0/16 via 192.0.2.2\nS 10.20.30.0/24 [200/0] via 192.0.2.3', choices: ['The /24 via 192.0.2.3', 'The /16 because 110 is less than 200', 'The /8 because static routes always win'], answer: 0, explanation: 'The /24 is installed and is the longest match. Its distance of 200 does not make the less-specific /16 win. Route-source preference compares candidates for the same prefix.' },
      { question: 'When does this floating static route become the selected route?', evidence: 'Same prefix: 10.20.0.0/16\nPrimary OSPF candidate: AD 110\nStatic candidate: AD 200; next hop reachable', choices: ['Whenever traffic is heavy', 'When the OSPF candidate is withdrawn and the static remains valid', 'Immediately, because all static routes beat OSPF'], answer: 1, explanation: 'The higher-distance static is a backup for the same prefix. It can become selected after the primary disappears. A static route alone does not monitor an application service’s health.' }
    ],
    lab: { task: 'Create a three-router lab with a primary and backup path. Configure a default or network static route, inspect its next hop, and break the primary link. Check both forward and return routes.', commands: 'show ip route\nshow ip route 10.20.30.40\nshow ip interface brief\nping 10.20.30.40\ntraceroute 10.20.30.40\n\nExample backup for the same prefix:\nip route 10.20.0.0 255.255.0.0 192.0.2.3 200', verify: ['The backup next hop must be reachable through a real path in your lab.', 'Verify the selected route before and after the primary is withdrawn.', 'Check the destination side’s return route rather than assuming one-way reachability is enough.'] }
  },
  ospf: {
    goal: 'Diagnose adjacency failures by checking compatible settings, and distinguish an expected 2-WAY state from a broken adjacency.',
    reasoning: [
      'Verify interface state and addressing before routing-protocol settings. For this numbered Ethernet link, the neighbors must be on the intended common subnet.',
      'Check area, hello/dead timers, authentication, passive configuration, and unique router IDs. OSPF process IDs are locally significant and need not match.',
      'On a broadcast network, the DR and BDR form full adjacencies with other routers. Two DROTHERs can remain 2-WAY normally.',
      'A router stuck in EXSTART or EXCHANGE needs a different investigation from one receiving no hellos. Inspect MTU and database exchange rather than changing random settings.'
    ],
    trap: 'Matching process IDs do not fix mismatched areas. Do not classify every 2-WAY neighbor as failed; first identify the network type and DR/BDR roles.',
    checkpoints: [
      { question: 'Which remaining difference blocks this adjacency?', evidence: 'Same subnet, area 0, unique router IDs, no authentication\nR1 process 1: hello 10, dead 40\nR2 process 20: hello 5, dead 20', choices: ['The process IDs must match', 'The router IDs must match', 'The hello/dead timers must match'], answer: 2, explanation: 'The timer mismatch prevents adjacency. Process 1 and process 20 can be neighbors because those IDs are local. Router IDs must be unique.' },
      { question: 'Is 2-WAY necessarily a failure in this case?', evidence: 'Four routers share an OSPF broadcast segment.\nDR and BDR already exist.\nR3 and R4 are both DROTHERs and see each other as 2-WAY.', choices: ['No; DROTHERs normally remain 2-WAY with each other', 'Yes; every router must be FULL with every other router', 'Yes; OSPF does not support more than two routers'], answer: 0, explanation: 'R3 and R4 need full adjacencies with the DR/BDR, not each other. The network type and neighbor roles explain the state.' }
    ],
    lab: { task: 'Use the original two-router link. Put both interfaces in area 0, verify FULL, then change one hello interval and diagnose the new failure. Use the actual interface name in your lab.', commands: 'Inspect:\nshow ip ospf interface GigabitEthernet0/0\nshow ip ospf neighbor\nshow ip protocols\n\nExample interface configuration:\ninterface GigabitEthernet0/0\n ip ospf 1 area 0', verify: ['On a two-router Ethernet segment, expect a full adjacency after compatible settings and election.', 'Check the interface’s area and timers, not just the router’s process declaration.', 'After a deliberate timer mismatch, explain the missing adjacency using the observed interface settings.'] }
  },
  nat: {
    goal: 'Interpret a translation table, distinguish address roles, and troubleshoot translation separately from routing and filtering.',
    reasoning: [
      'Inside local is the internal host’s address as seen inside, such as 10.0.0.10. Inside global is its translated address visible outside, such as 203.0.113.5.',
      'PAT can translate source ports so several sessions share one address. The translation includes protocol and endpoint information to demultiplex replies.',
      'Translation needs correct inside/outside interface roles and eligible traffic. A source-selection ACL for NAT is not the same as an interface filtering ACL.',
      'NAT is only one part of delivery. Check routes, ACLs, and the return path even when the translation looks correct. Ordinary dynamic PAT does not provide a fixed mapping for unsolicited inbound traffic.'
    ],
    trap: 'A public-looking IP in a translation table does not prove Internet access. The 203.0.113.0/24 addresses here are documentation addresses for a closed lab.',
    checkpoints: [
      { question: 'Which address is inside global in this row?', evidence: 'Pro  Inside global        Inside local       Outside global\ntcp  203.0.113.5:40001    10.0.0.10:51500     198.51.100.20:443', choices: ['10.0.0.10', '203.0.113.5', '198.51.100.20'], answer: 1, explanation: '203.0.113.5 represents the internal host to the outside. 10.0.0.10 is inside local; 198.51.100.20 is the external server.' },
      { question: 'What does an existing PAT entry prove?', evidence: 'A client connection has a translation entry.\nThe application still times out.', choices: ['The server application is healthy', 'Both directions are permitted by every firewall', 'Translation occurred; routing, filtering, and the remote service still need checking'], answer: 2, explanation: 'A translation entry shows NAT state for the flow. It does not establish that packets reached the server or that replies can return. Test the path and service independently.' }
    ],
    lab: { task: 'In a closed lab, use two inside clients and an outside server. Configure NAT overload on the edge router, create client sessions, and inspect translations. Substitute the lab’s actual outside interface.', commands: 'Example global configuration:\naccess-list 1 permit 10.0.0.0 0.0.0.255\nip nat inside source list 1 interface GigabitEthernet0/1 overload\ninterface GigabitEthernet0/0\n ip nat inside\ninterface GigabitEthernet0/1\n ip nat outside\n\nVerify:\nshow ip nat translations\nshow ip nat statistics\nshow ip route', verify: ['Interfaces also need correct addresses and working routes; these commands are only the NAT portion.', 'Generate traffic before expecting dynamic entries.', 'Record inside local/global addresses and translated ports for both clients.'] }
  },
  dhcp: {
    goal: 'Trace DHCP through a relay and distinguish address assignment failures from DNS and gateway failures.',
    reasoning: [
      'A new client initially lacks a usable IP configuration and broadcasts DHCPDISCOVER. The usual exchange is Discover, Offer, Request, Acknowledge.',
      'The client-facing Layer 3 interface receives the broadcast. A relay forwards it to the server and identifies the original client subnet using the relay address field.',
      'The server needs a matching scope, available addresses, correct mask/router/DNS options, and a path back to the relay. DHCP typically uses UDP server port 67 and client port 68.',
      'Once a lease is valid, test the gateway, a remote IP, and then name resolution. Each test separates a different stage instead of treating every failure as DHCP.'
    ],
    trap: 'Configure the relay where client broadcasts arrive, not just on the interface facing the server. A valid lease can still contain an incorrect DNS server or gateway.',
    checkpoints: [
      { question: 'Where does the helper address belong?', evidence: 'R1 Gi0/0: client LAN 10.10.20.1/24\nR1 Gi0/1: server-facing LAN 10.10.50.1/24\nServer: 10.10.50.10', choices: ['On Gi0/0, the client-facing interface', 'Only on Gi0/1, because it is near the server', 'On every Layer 2 access port'], answer: 0, explanation: 'Gi0/0 receives DHCP broadcasts from the clients. That interface relays requests to 10.10.50.10 and identifies 10.10.20.0/24 to the server.' },
      { question: 'Which service should you investigate next?', evidence: 'Lease: valid address, mask, gateway\nPing to gateway: works\nConnection to remote service by IP: works\nConnection using its hostname: fails', choices: ['Spanning tree root election', 'DNS configuration and name resolution', 'The DHCP relay must be removed'], answer: 1, explanation: 'IP connectivity to the service works, but name-based access fails. Check the configured DNS server and its answer. The lease may have supplied an incorrect DNS option.' }
    ],
    lab: { task: 'Create separate client and DHCP-server LANs. Give the server a scope for the client LAN and a route back. Add the relay, request a lease, then deliberately change the scope’s DNS option.', commands: 'On client-facing router interface:\ninterface GigabitEthernet0/0\n ip helper-address 10.10.50.10\n\nRouter verification:\nshow running-config interface GigabitEthernet0/0\nshow ip route\n\nClient verification:\nipconfig /all\nnslookup example.test', verify: ['Confirm address, mask, default gateway, and DNS server in the received lease.', 'In simulation mode, identify the relay’s request and the server’s response.', 'A changed server option can require renewing the lease before the client sees it; compare IP access with name-based access.'] }
  },
  acl: {
    goal: 'Evaluate packets against ordered ACL entries, including direction, wildcard masks, source/destination ports, and implicit deny.',
    reasoning: [
      'Write the packet’s protocol, source address/port, and destination address/port before examining the ACL. Reversing these fields changes the result.',
      'Walk entries from lowest sequence number upward. The first match determines the action; later permits cannot rescue an earlier matching deny.',
      'In a wildcard mask, 0 means compare this bit and 1 means ignore it. 0.0.0.255 matches a /24, not an arbitrary last-octet range.',
      'Direction is relative to the router interface. If no entry matches, implicit deny applies. Ordinary ACLs are stateless, so the reverse flow must be considered separately.'
    ],
    trap: 'eq 22 after the destination matches the destination port. A source port of 51000 does not avoid that deny. A NAT selection ACL has a different purpose from an applied filtering ACL.',
    checkpoints: [
      { question: 'How are these two packets treated?', evidence: 'Same ACL as the foundation:\n10 deny tcp 10.10.20.0 0.0.0.255 any eq 22\n20 permit ip 10.10.20.0 0.0.0.255 any\nA: 10.10.20.15 → server TCP/443\nB: 10.10.30.15 → server TCP/443', choices: ['Both permitted by line 20', 'A denied, B permitted', 'A permitted by line 20; B denied implicitly'], answer: 2, explanation: 'A does not match the SSH deny and matches the source subnet permit. B matches neither entry, so the implicit deny drops it.' },
      { question: 'How do you permit this one host’s SSH while keeping the subnet-wide deny?', evidence: 'Current first entry: sequence 10 deny SSH from 10.10.20.0/24\nException: permit 10.10.20.15 to 198.51.100.20 TCP/22', choices: ['Insert a specific permit before sequence 10', 'Append the specific permit after sequence 20', 'Change the client’s source port'], answer: 0, explanation: 'A specific permit must precede the broader matching deny. For a named ACL, a suitable earlier sequence could permit tcp host 10.10.20.15 host 198.51.100.20 eq 22.' }
    ],
    lab: { task: 'Apply a named extended ACL inbound on a lab client-facing router interface. Test SSH and HTTPS to a server, then add a specific SSH exception before the deny.', commands: 'ip access-list extended CLIENTS\n 10 deny tcp 10.10.20.0 0.0.0.255 any eq 22\n 20 permit ip 10.10.20.0 0.0.0.255 any\ninterface GigabitEthernet0/0\n ip access-group CLIENTS in\n\nVerify:\nshow access-lists CLIENTS\nshow ip interface GigabitEthernet0/0', verify: ['The server must actually run the tested services; a closed port is not proof of an ACL drop.', 'Check the applied interface and direction and observe matching entry counters.', 'Verify the exception appears before the deny and retest all affected flows, including replies.'] }
  },
  wireless: {
    goal: 'Diagnose wireless failures in order: radio visibility, association/security, VLAN/DHCP, and then routed applications.',
    reasoning: [
      'Seeing an SSID proves discovery, not successful authentication. Compare the WLAN security mode with the client profile and credentials.',
      'WPA2-Personal uses a shared key; Enterprise uses individual authentication through an AAA service, commonly RADIUS. Those failure paths require different evidence.',
      'After authentication, the WLAN must map to a working VLAN and a reachable DHCP service. Strong signal does not fix a trunk or VLAN mapping mistake.',
      'For the common 2.4 GHz channel plan with 20 MHz channels, 1, 6, and 11 avoid overlap. Wider channels, regional rules, and interference change planning decisions.'
    ],
    trap: 'A successful security exchange with no address is a different failure from a bad PSK. DNS only becomes relevant after working IP connectivity.',
    checkpoints: [
      { question: 'What should you investigate after authentication succeeds but DHCP fails?', evidence: 'Client security handshake: successful\nSignal: strong\nNo usable DHCP lease\nFlexConnect local switching; DHCP is reached through the local VLAN.\nWLAN maps to VLAN 30; AP uplink trunk permits only 10,20\nVLAN 30 exists; its DHCP scope and gateway are verified.', choices: ['Change the AP management native VLAN to 30 without extending the allowed list', 'Permit VLAN 30 on the intended uplink and verify the DHCP path', 'Add VLAN 30 only to the controller uplink while keeping the AP trunk unchanged'], answer: 1, explanation: 'With FlexConnect local switching, client DHCP traffic leaves the AP in VLAN 30, which the AP trunk excludes. Add VLAN 30 to that allowed list. Changing the management native VLAN does not allow the missing client VLAN; changing only the controller uplink does not fix this local path. For centrally switched traffic, investigate the controller-side VLAN path instead.' },
      { question: 'Which design supplies individual user authentication?', evidence: 'Requirement: employee-specific credentials and centralized authentication\nAvoid a single shared WLAN password.', choices: ['WPA2-Personal with one PSK for everyone', 'An open SSID with a hidden name', 'WPA2-Enterprise with an appropriate RADIUS service'], answer: 2, explanation: 'Enterprise authentication supports individual credentials through an AAA service. Hiding an SSID is not authentication, and a shared PSK does not supply per-user identities.' }
    ],
    lab: { task: 'Use a FlexConnect AP with local switching, a controller, a client, and DHCP reachable through the local client VLAN. Configure a WPA2-Personal WLAN, verify a join, then independently break the client key and the WLAN VLAN path.', commands: 'WLAN settings to inspect:\nSSID: StudyLab\nSecurity: WPA2-Personal / AES\nClient key matches the configured lab key\nWLAN-to-VLAN mapping\nAP uplink allowed VLANs for locally switched client traffic\n\nWired switch:\nshow interfaces trunk\nshow vlan brief', verify: ['With the wrong key, identify the failed security stage before DHCP.', 'With the correct key but broken VLAN path, confirm authentication succeeds while address assignment fails.', 'With both repaired, verify a valid lease, gateway access, and then the target application.'] }
  },
  api: {
    goal: 'Interpret API requests and JSON, distinguish control/data planes, and choose an automation mechanism based on its role.',
    reasoning: [
      'GET reads a resource representation. POST commonly creates or invokes an action; PUT commonly replaces a resource; PATCH updates part of one; DELETE removes one. Exact API behavior is defined by its contract.',
      'JSON objects use key/value pairs, arrays contain ordered values, and strings, numbers, Booleans, and null are distinct types. A successful HTTP status is not proof of end-to-end traffic delivery.',
      'The control plane decides how traffic should flow; the data plane forwards packets. Controller northbound APIs typically connect applications to the controller, and southbound interfaces connect toward network devices.',
      'Ansible commonly automates configuration tasks through playbooks; Terraform manages declared infrastructure and state. Predictive AI estimates outcomes or patterns; generative AI creates content such as suggested configurations that still require validation.'
    ],
    trap: 'A returned enabled: true value can describe administrative configuration without proving operational link state. Never assume a generated command is correct merely because it looks plausible.',
    checkpoints: [
      { question: 'Which request most directly expresses a partial update under this API contract?', evidence: 'Contract: PATCH accepts changed fields only.\nGoal: disable Gi0/1 without replacing other properties.', choices: ['PATCH /api/interfaces/Gi0%2F1 with {"enabled": false}', 'GET /api/interfaces/Gi0%2F1 with no body', 'DELETE /api/interfaces with no body'], answer: 0, explanation: 'Under the supplied contract, PATCH with a Boolean false updates only the named field. GET reads; deleting the collection does not express a targeted partial update. Real APIs require appropriate authentication and documented request formats.' },
      { question: 'What can you conclude from this response?', evidence: 'HTTP 200 OK\n{"name":"Gi0/1","enabled":true,"operStatus":"down"}', choices: ['Traffic is forwarding because enabled is true', 'The interface is administratively enabled but operationally down', 'The JSON is invalid because true must be quoted'], answer: 1, explanation: 'The fields distinguish administrative intent from operational observation. true is a valid JSON Boolean. Inspect link, cable, peer, and device state before assuming connectivity.' }
    ],
    lab: { task: 'Using a local sample response, annotate each JSON value’s type and write a proposed read and partial-update request. Explain how you would verify a change on the device before trusting the API response.', commands: 'Read request:\nGET /api/interfaces\n\nProposed partial update (illustrative API):\nPATCH /api/interfaces/Gi0%2F1\nContent-Type: application/json\n{"enabled": false}\n\nFollow-up read:\nGET /api/interfaces/Gi0%2F1', verify: ['Explain the difference between request success and operational network success.', 'Confirm the API contract, authentication, and authorization before sending real changes.', 'Compare returned configuration with device state and a meaningful traffic test.'] }
  }
};
