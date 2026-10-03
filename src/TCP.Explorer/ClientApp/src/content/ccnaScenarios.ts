export interface ScenarioQuestion {
  phase: 'Predict' | 'Diagnose' | 'Verify';
  prompt: string;
  evidence: string;
  correct: string;
  distractors: string[];
  explanation: string;
}
export interface NetworkScenario {
  id: string;
  title: string;
  objective: string;
  brief: string;
  nodes: string[];
  links: string[];
  topology: string;
  baseline: string;
  fault: string;
  repair: string;
  checks: string[];
  questions: ScenarioQuestion[];
}

/** Original study cases with authored diagrams, configuration examples, and illustrative evidence. */
export const ccnaScenarios: NetworkScenario[] = [
  {
    id: 'vlan', title: 'A VLAN stops at the trunk', objective: '2.1 / 2.2',
    brief: 'Two PCs in VLAN 20 share a /24 across two switches. Preserve VLAN 10 while restoring their connection. All links are up; VLAN 20 exists and STP permits forwarding.',
    nodes: ['PC-A', 'SW1', 'SW2', 'PC-B'], links: ['VLAN 20', '802.1Q', 'VLAN 20'],
    topology: 'PC-A Fa0 → SW1 Fa0/1; SW1 Fa0/2 → SW2 Fa0/2; SW2 Fa0/1 → PC-B Fa0. PCs: 192.0.2.10/24 and 192.0.2.20/24. No gateway is needed for this same-subnet test.',
    baseline: 'Use two Layer 2 switches and two PCs. Cable as shown; assign the static PC addresses. On BOTH switches:\nenable\nconfigure terminal\nvlan 10\nvlan 20\ninterface FastEthernet0/1\n switchport mode access\n switchport access vlan 20\n no shutdown\ninterface FastEthernet0/2\n switchport mode trunk\n switchport trunk allowed vlan 10,20\n no shutdown\nend\n\nFrom PC-A: ping 192.0.2.20. Wait for STP/ARP and repeat before saving the baseline.',
    fault: 'On SW2:\nconfigure terminal\ninterface FastEthernet0/2\n switchport trunk allowed vlan 10\nend',
    repair: 'On SW2:\nconfigure terminal\ninterface FastEthernet0/2\n switchport trunk allowed vlan add 20\nend',
    checks: ['Before the fault, repeat ping until the baseline succeeds.', 'During the fault, inspect show interfaces trunk on both switches; only SW2 excludes VLAN 20.', 'After repair, both trunks list 10,20 as allowed and VLAN 20 as active/forwarding. Repeat the ping and inspect show mac address-table dynamic.'],
    questions: [
      { phase: 'Predict', prompt: 'With this baseline, how does PC-A reach PC-B?', evidence: 'PC-A: 192.0.2.10/24\nPC-B: 192.0.2.20/24\nBoth access ports: VLAN 20\nBoth trunks: VLANs 10,20 allowed and forwarding', correct: 'ARP for PC-B, then switch frames through VLAN 20', distractors: ['ARP for a default gateway, then route between the PCs', 'Send frames through VLAN 10 because it is also allowed', 'Send to PC-B only after adding a host route on each switch'], explanation: 'Both hosts are in the same subnet and VLAN. ARP resolves the peer MAC; switches carry the frames through VLAN 20. A routed gateway or switch host route is unnecessary.' },
      { phase: 'Diagnose', prompt: 'Which change restores the path without removing existing trunk traffic?', evidence: 'After the fault:\nSW1 Fa0/2 allowed VLANs: 10,20\nSW2 Fa0/2 allowed VLANs: 10\nPC-A → PC-B ping: fails\nAccess membership, addresses, and STP state are unchanged.', correct: 'On SW2 Fa0/2: switchport trunk allowed vlan add 20', distractors: ['On SW2 Fa0/2: switchport trunk allowed vlan 20', 'On SW2 Fa0/1: switchport access vlan 10', 'On SW1 Fa0/2: switchport trunk native vlan 20'], explanation: 'Adding VLAN 20 repairs the asymmetric allowed list while retaining VLAN 10. Replacing the list with 20 removes existing traffic; access or native VLAN changes do not repair the intended tagged path.' },
      { phase: 'Verify', prompt: 'Which evidence best establishes that the repair works?', evidence: 'The repair command was accepted. You must verify the VLAN path and actual delivery.', correct: 'VLAN 20 allowed/active/forwarding at both ends, plus successful repeated PC-to-PC ping', distractors: ['Both trunk interfaces show physical up, without a traffic test', 'VLAN 20 appears in show vlan brief on SW1 only', 'PC-A has an ARP entry from before the fault'], explanation: 'Configuration acceptance and link state alone do not establish VLAN forwarding. Check both ends and traffic; a cached ARP entry may predate the fault.' }
    ]
  },
  {
    id: 'ospf', title: 'Neighbors that will not form', objective: '3.4',
    brief: 'Two routers advertise their loopbacks through a single-area OSPF link. Determine why routes disappear even though the cable stays up.',
    nodes: ['Lo0 on R1', 'R1', 'R2', 'Lo0 on R2'], links: ['10.1.1.1/32', '192.0.2.0/30', '10.2.2.2/32'],
    topology: 'Use two routers with OSPF support. R1 Gi0/0 (192.0.2.1/30) connects to R2 Gi0/0 (192.0.2.2/30). Both use area 0, default broadcast network type, no authentication, unique router IDs, and no passive transit interface.',
    baseline: 'On R1:\nenable\nconfigure terminal\ninterface GigabitEthernet0/0\n ip address 192.0.2.1 255.255.255.252\n no shutdown\ninterface Loopback0\n ip address 10.1.1.1 255.255.255.255\nrouter ospf 1\n router-id 1.1.1.1\n network 192.0.2.0 0.0.0.3 area 0\n network 10.1.1.1 0.0.0.0 area 0\nend\n\nOn R2, use 192.0.2.2/30 on Gi0/0, 10.2.2.2/32 on Loopback0, router-id 2.2.2.2, and process 20. Network statements: 192.0.2.0 0.0.0.3 area 0 and 10.2.2.2 0.0.0.0 area 0.\nVerify FULL with show ip ospf neighbor and both remote loopback routes with show ip route ospf.',
    fault: 'On R2:\nconfigure terminal\ninterface GigabitEthernet0/0\n ip ospf hello-interval 5\nend\nWait beyond the original dead interval before collecting the failed-neighbor evidence.',
    repair: 'On R2:\nconfigure terminal\ninterface GigabitEthernet0/0\n no ip ospf hello-interval\nend',
    checks: ['Confirm the baseline reaches FULL and ping the remote loopback in each direction.', 'Compare show ip ospf interface GigabitEthernet0/0 on both devices after the fault. The hello intervals differ.', 'After repair, allow convergence. Confirm FULL, matching 10/40 timers, learned OSPF routes, and remote loopback pings.'],
    questions: [
      { phase: 'Predict', prompt: 'Can these routers form a full adjacency at baseline?', evidence: 'R1: process 1, router ID 1.1.1.1, area 0, hello/dead 10/40\nR2: process 20, router ID 2.2.2.2, area 0, hello/dead 10/40\nTransit interfaces: up/up, same /30, default broadcast type', correct: 'Yes; process IDs are local and the stated neighbor parameters agree', distractors: ['No; process 1 and process 20 must be identical', 'No; both routers must share the same router ID', 'No; a /30 Ethernet segment cannot elect a DR and BDR'], explanation: 'The process number is locally significant. Unique router IDs and compatible link parameters allow adjacency. A two-router broadcast Ethernet segment still elects DR/BDR.' },
      { phase: 'Diagnose', prompt: 'Which mismatch accounts for the lost adjacency?', evidence: 'After the dead interval has elapsed:\nR1 Gi0/0: area 0, hello 10, dead 40\nR2 Gi0/0: area 0, hello 5, dead 40\nBoth links up/up; no FULL neighbor; no authentication configured', correct: 'R2’s hello interval differs from R1’s', distractors: ['R2 uses a different OSPF process number', 'The two routers have different host addresses in the /30', 'Both routers use the same area number'], explanation: 'OSPF hello/dead intervals must agree on this link. Different addresses and process IDs are normal; a matching area is required, not a fault.' },
      { phase: 'Verify', prompt: 'What should you check after restoring the timer?', evidence: 'R2’s hello interval is restored to the default. Interfaces remain up/up.', correct: 'FULL neighbor state, learned remote loopback routes, and successful remote-loopback pings', distractors: ['A successful ping to the directly connected peer address only', 'Matching process numbers in the running configurations', 'An up/up interface and a local connected loopback route only'], explanation: 'A directly connected ping can work without OSPF. FULL plus learned remote prefixes and successful traffic verifies adjacency, route installation, and delivery.' }
    ]
  },
  {
    id: 'routes', title: 'The more specific route wins', objective: '3.2 / 3.3',
    brief: 'R1 has a preferred path and a backup path to a server LAN. A newly added host route sends one server toward the wrong next hop.',
    nodes: ['PC-A', 'R1', 'R2 / R3', 'Server'], links: ['192.0.2.0/24', 'two routed paths', '10.20.30.0/24'],
    topology: 'PC-A 192.0.2.10/24, gateway .1 → R1 Gi0/0 .1/24. R1 Gi0/1 198.51.100.1/30 → R2 Gi0/0 .2/30. R1 Gi0/2 198.51.100.5/30 → R3 Gi0/0 .6/30. R2 Gi0/1 10.20.30.1/24 and R3 Gi0/1 10.20.30.2/24 join a Layer 2 switch with server 10.20.30.40/24, gateway 10.20.30.1. Use three routers; enable all cabled interfaces.',
    baseline: 'Assign the addresses from the topology with ip address ADDRESS MASK and no shutdown under each router interface. Assign static addresses to the PC and server. On R1, global configuration:\nip route 10.20.30.0 255.255.255.0 198.51.100.2\nip route 10.20.30.0 255.255.255.0 198.51.100.6 200\nOn R2:\nip route 192.0.2.0 255.255.255.0 198.51.100.1\nOn R3:\nip route 192.0.2.0 255.255.255.0 198.51.100.5\naccess-list 101 deny ip any host 10.20.30.40\naccess-list 101 permit ip any any\ninterface GigabitEthernet0/1\n ip access-group 101 out\nend\nThe R3 policy is deliberate: this server must use R2.\nVerify PC-A can ping 10.20.30.40 before saving.',
    fault: 'On R1, global configuration:\nip route 10.20.30.40 255.255.255.255 198.51.100.6 200\nend',
    repair: 'On R1, global configuration:\nno ip route 10.20.30.40 255.255.255.255 198.51.100.6 200\nend\nKeep the network routes and the deliberate R3 policy.',
    checks: ['Before fault injection, R1 selects the /24 through R2 and PC-A reaches the server.', 'During the fault, show ip route 10.20.30.40 selects the /32 via R3 despite AD 200. Inspect R3 ACL counters while testing.', 'After removing the /32, R1 selects the /24 via R2; repeated PC-to-server ping succeeds.'],
    questions: [
      { phase: 'Predict', prompt: 'Which installed route carries the packet to 10.20.30.40?', evidence: 'R1 installed routes after a change:\nS 10.20.30.0/24 [1/0] via 198.51.100.2\nS 10.20.30.40/32 [200/0] via 198.51.100.6', correct: 'The /32 via 198.51.100.6', distractors: ['The /24 via 198.51.100.2 because its distance is lower', 'Both next hops because both routes are static', 'Neither next hop because administrative distance 200 is unusable'], explanation: 'Forwarding uses longest prefix match among installed routes. The /32 wins over the /24; administrative distance compares candidates for the same prefix.' },
      { phase: 'Diagnose', prompt: 'Which minimal change restores the intended server path?', evidence: 'Required server path: R2 (198.51.100.2)\nR1 has the /24 and /32 above.\nR3 deliberately denies traffic to 10.20.30.40; its deny counter rises.\nR2’s server path and return route are verified.', correct: 'Remove the unintended /32 route through R3', distractors: ['Lower the /24 administrative distance to 1', 'Raise the /32 administrative distance from 200 to 220', 'Add another /24 route through R2 with distance 5'], explanation: 'Removing the /32 exposes the working /24. The /24 already has distance 1, and changing distances while keeping an installed /32 does not defeat longest prefix matching.' },
      { phase: 'Verify', prompt: 'Which result confirms the intended forwarding decision and delivery?', evidence: 'The unintended host route has been removed; the R3 access policy remains.', correct: 'Destination lookup selects the /24 via R2 and repeated PC-to-server ping succeeds', distractors: ['The running configuration contains a /24 route only, without inspecting installed state', 'R1 can ping the R3 transit address', 'R3’s server-facing interface is up/up'], explanation: 'Inspect the installed route for the exact destination and test end-to-end delivery. Configuration presence, an unrelated next-hop ping, or link state is insufficient.' }
    ]
  },
  {
    id: 'acl', title: 'An exception in the wrong place', objective: '5.6',
    brief: 'Allow one administrator to reach a server over HTTPS while denying HTTPS from other clients. Read the ACL in order and retain the broader policy.',
    nodes: ['Admin / Client', 'R1', 'SW2', 'HTTPS server'], links: ['10.10.20.0/24', '198.51.100.0/24', 'TCP 443'],
    topology: 'Two PCs connect through SW1 to R1 Gi0/0 10.10.20.1/24: Admin .15 and Client .16, both gateway .1. R1 Gi0/1 198.51.100.1/24 → Server .20/24, gateway .1. Use a router, a Layer 2 switch, and an HTTPS-enabled server.',
    baseline: 'Assign the topology addresses; enable both router interfaces. On R1:\nenable\nconfigure terminal\nip access-list extended CLIENTS\n 5 permit tcp host 10.10.20.15 host 198.51.100.20 eq 443\n 10 deny tcp 10.10.20.0 0.0.0.255 host 198.51.100.20 eq 443\n 20 permit ip 10.10.20.0 0.0.0.255 any\ninterface GigabitEthernet0/0\n ip access-group CLIENTS in\nend\nFrom each PC browser, request https://198.51.100.20. Admin should work; Client should fail. Verify the server actually supports and serves HTTPS.',
    fault: 'On R1:\nconfigure terminal\nip access-list extended CLIENTS\n no 5\n 15 permit tcp host 10.10.20.15 host 198.51.100.20 eq 443\nend',
    repair: 'On R1:\nconfigure terminal\nip access-list extended CLIENTS\n no 15\n 5 permit tcp host 10.10.20.15 host 198.51.100.20 eq 443\nend',
    checks: ['Verify interface direction with show ip interface GigabitEthernet0/0 and ACL order with show access-lists CLIENTS.', 'Start fresh HTTPS requests from both clients; record counter changes rather than treating cumulative counts as new traffic.', 'After repair Admin HTTPS succeeds, Client HTTPS remains blocked, and permitted ICMP still works.'],
    questions: [
      { phase: 'Predict', prompt: 'How does this inbound ACL handle the administrator’s HTTPS request?', evidence: '10 deny tcp 10.10.20.0 0.0.0.255 host 198.51.100.20 eq 443\n15 permit tcp host 10.10.20.15 host 198.51.100.20 eq 443\n20 permit ip 10.10.20.0 0.0.0.255 any\nPacket: TCP 10.10.20.15:51000 → 198.51.100.20:443', correct: 'Line 10 denies it before line 15 is reached', distractors: ['Line 15 permits it because the source is more specific', 'Line 20 permits it because the last matching entry wins', 'It bypasses line 10 because the source port is not 443'], explanation: 'ACLs stop at the first match. Line 10 covers this source, destination, and destination port. Specificity does not reorder ACL entries.' },
      { phase: 'Diagnose', prompt: 'Which edit permits the administrator while preserving the other-client restriction?', evidence: 'The server is listening on TCP/443. The ACL shown above is applied inbound on the client-facing interface. Both client HTTPS requests are denied.', correct: 'Move the host-specific permit to sequence 5', distractors: ['Move the host-specific permit to sequence 25', 'Delete the subnet-wide deny at sequence 10', 'Change the deny destination port from 443 to 22'], explanation: 'The specific exception must precede the broad deny. Removing or changing the deny would allow unwanted HTTPS; placing the exception later leaves it unreachable.' },
      { phase: 'Verify', prompt: 'Which test verifies both the exception and the retained restriction?', evidence: 'The specific permit is now sequence 5. Other entries are unchanged.', correct: 'Admin HTTPS succeeds, Client HTTPS fails, and the corresponding permit/deny counters increase', distractors: ['Admin ping succeeds and the server interface is up', 'Both clients can ping, without attempting HTTPS', 'The ACL exists but its interface attachment is not checked'], explanation: 'Test both intended permission and intended denial with the actual protocol. ICMP success does not test TCP/443 policy; counter changes connect observations to ACL processing.' }
    ]
  },
  {
    id: 'pat', title: 'Two clients, one translated address', objective: '4.1',
    brief: 'Two clients use NAT overload to reach a server in a closed lab. Interpret translation identities, then diagnose a missing NAT interface role.',
    nodes: ['PC-A / PC-B', 'SW1', 'R1', 'Server'], links: ['10.0.0.0/24', 'inside', '203.0.113.0/24'],
    topology: 'PC-A 10.0.0.10/24 and PC-B 10.0.0.11/24, gateway 10.0.0.1 → Layer 2 switch → R1 Gi0/0 10.0.0.1/24. R1 Gi0/1 203.0.113.5/24 → Server 203.0.113.20/24. Server has HTTP enabled and no gateway; successful replies require translation to the directly connected outside subnet. Documentation addresses stay inside this lab.',
    baseline: 'Use a router with NAT overload support. Assign topology addresses and enable both interfaces. On R1:\nenable\nconfigure terminal\naccess-list 1 permit 10.0.0.0 0.0.0.255\nip nat inside source list 1 interface GigabitEthernet0/1 overload\ninterface GigabitEthernet0/0\n ip nat inside\ninterface GigabitEthernet0/1\n ip nat outside\nend\nFrom both PC browsers, request http://203.0.113.20. Inspect show ip nat translations while sessions are active. Session source ports may differ from the illustrative question.',
    fault: 'On R1:\nconfigure terminal\ninterface GigabitEthernet0/1\n no ip nat outside\nend\nclear ip nat translation *\nStart new HTTP requests from both PCs.',
    repair: 'On R1:\nconfigure terminal\ninterface GigabitEthernet0/1\n ip nat outside\nend\nStart new client HTTP requests.',
    checks: ['Before fault injection, both clients retrieve the page and translations identify their distinct inside-local addresses.', 'After the fault, inspect show ip nat statistics and running configuration: Gi0/1 is missing from outside interfaces.', 'After repair, new translations appear and both HTTP requests succeed. Record actual ports rather than assuming the illustrative values.'],
    questions: [
      { phase: 'Predict', prompt: 'Which inside client receives a matching TCP reply addressed to 203.0.113.5:40002?', evidence: 'Illustrative active translations (abbreviated):\nInside global           Inside local\n203.0.113.5:40001       10.0.0.10:51500\n203.0.113.5:40002       10.0.0.11:51500\nBoth TCP sessions target 203.0.113.20:80.', correct: '10.0.0.11:51500', distractors: ['10.0.0.10:51500', 'Both clients because the global IP is shared', 'Neither client because their local source ports match'], explanation: 'PAT distinguishes the active mappings by protocol and translated endpoints. Port 40002 maps to PC-B; equal original client ports do not prevent separate translations.' },
      { phase: 'Diagnose', prompt: 'Which missing setting explains why new client requests have no translations?', evidence: 'R1 interfaces up/up; connected routes present\nACL 1 permits 10.0.0.0/24\nInside-source interface overload rule is present\nshow ip nat statistics (abbreviated):\n Inside interfaces: GigabitEthernet0/0\n Outside interfaces: none\nOld translations cleared; new HTTP requests produce none.', correct: 'ip nat outside on GigabitEthernet0/1', distractors: ['ip nat inside on GigabitEthernet0/1', 'Remove overload from the inside-source rule', 'Add a static route for the already-connected server subnet'], explanation: 'The translation path lacks its outside role. Marking both interfaces inside does not establish it; removing overload defeats the shared-address design; the connected route already exists.' },
      { phase: 'Verify', prompt: 'What confirms that the repaired PAT path supports both clients?', evidence: 'The outside role has been restored. Generate new HTTP traffic before inspecting state.', correct: 'Distinct client translations and successful HTTP responses at both PCs', distractors: ['An outside address in the configuration without traffic', 'Successful ping from R1 to the server only', 'A translation row for PC-A without checking PC-B or either response'], explanation: 'New translations establish NAT state, while actual responses verify delivery. Router-originated ping does not exercise the same inside-client PAT path.' }
    ]
  }
];
