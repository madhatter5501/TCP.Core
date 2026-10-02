# CCNA bank coverage and maintenance

Content review: October 2, 2026. Target: CCNA 200-301 v1.1. Cisco's [published checklist](https://learningcontent.cisco.com/documents/marketing/exam-topics/200-301-CCNA-v1.1.pdf) is the scope reference. This matrix is an editorial record, maintained separately from generated question counts. It records representative assessments rather than asserting complete skill coverage.

The bank retains 200 questions with domain counts 40/40/50/20/30/20. Parent tags represent all 53 objectives. Multiple-choice answers, including configuration selections, cannot establish successful hands-on execution. Topic reading links are provided after each checked answer; they are references rather than an endorsement or provenance certification. The questions are practice material, not actual exam items, and their scores are not a validated prediction of exam performance.

## Parent-objective matrix

Question IDs are explicit identities, independent of their location in a file. Each row identifies representative samples; other questions can also touch the topic. All rows need the official checklist and, where applicable, a device or Packet Tracer lab for further preparation.

| Code | Representative IDs | Assessment scope and remaining practice |
| --- | --- | --- |
| 1.1 | fundamentals-001–006, 008 | Component roles; add broader endpoint/server and platform examples in study/labs. |
| 1.2 | fundamentals-009–013 | Architecture recognition; design and compare real campus, data-center, branch, and cloud paths. |
| 1.3 | fundamentals-ethernet-medium, 014–015 | Shared-medium/point-to-point behavior, reach and media; inspect supported optics and cabling. |
| 1.4 | fundamentals-016–017 | Duplex/CRC scenarios; inspect counters and isolate faults in a lab. |
| 1.5 | fundamentals-018–019 | TCP/UDP service tradeoffs; inspect live transport behavior. |
| 1.6 | fundamentals-020–024 | Calculated subnet boundaries, capacity, VLSM, and local-subnet verification; configure interfaces and verify routes. |
| 1.7 | fundamentals-private-ranges | Direct assessment of all three RFC 1918 CIDR blocks and their boundaries; apply them in an address plan. |
| 1.8 | fundamentals-026, fundamentals-ipv6-interface | IPv6 expansion and missing address/prefix command from interface evidence; configure and verify a routed topology. |
| 1.9 | fundamentals-ipv6-scope, fundamentals-029–031, fundamentals-ipv6-multicast | Global-unicast format versus link-local route next-hop scope, ULA, anycast, EUI-64, and multicast; practice group/scope behavior. Documentation addresses are explicitly distinguished from usable public allocations. |
| 1.10 | fundamentals-windows-gateway, fundamentals-host-routes | Interpret illustrative Windows address/mask/gateway evidence and Linux/macOS default routes; collect and compare actual host output. |
| 1.11 | fundamentals-034, 036 | Channels and RF troubleshooting; SSID/security also appear in access/security samples; survey and verify WLAN behavior. |
| 1.12 | fundamentals-037–038 | VM/container and VRF recognition; create isolated routing/virtual networking examples. |
| 1.13 | fundamentals-039, fundamentals-mac-aging | MAC learning plus direct aging/unknown-unicast forwarding scenario; inspect and manipulate a real MAC table. |
| 2.1 | access-001–005 | VLAN/data/voice/default VLAN and inter-VLAN requirements; build a multi-switch VLAN topology. |
| 2.2 | access-006–009 | Trunk, tag, native VLAN, allowed/active/forwarding checks; verify the full path. |
| 2.3 | access-010–011, access-lldp-enable | Discovery identity, CDP verification command, and concrete LLDP configuration; verify both protocols' neighbor output. |
| 2.4 | access-013–016 | LACP negotiation, consistency, Layer 3 channel direction, per-flow hashing; configure and verify L2 and L3 bundles. |
| 2.5 | access-017–026 | Root/port elections, roles, states, edge behavior, and protection mechanisms; verify failover and guards. |
| 2.6 | access-027–030 | Controller architecture, local/FlexConnect/monitor modes; compare additional supported AP modes. |
| 2.7 | access-031–033 | AP trunk, WLC aggregation compatibility, VLAN/DHCP path; verify physical and logical links. |
| 2.8 | access-034–037 | CLI/web/console/cloud access; AAA protocol reading also in 5.8; configure platform-appropriate management. |
| 2.9 | access-central-switching, access-wlan-path, access-040 | Read representative WLAN GUI fields, reconcile central switching with AP/controller trunk evidence, and interpret QoS meaning; navigate an actual supported WLC GUI. |
| 3.1 | connectivity-001–008 | Route code, prefix, mask, next hop, distance, cost, default, local route; inspect a populated device table. |
| 3.2 | connectivity-009–018 | Prefix selection, source preference, cost, ECMP, unresolved next hop; verify packet forwarding. |
| 3.3 | connectivity-019–030 | IPv4/IPv6 default/network/host/backup routing and return paths; configure and fail over routes in a lab. |
| 3.4 | connectivity-031–045 | OSPF parameters, neighbor/election behavior, IDs, network statement, reference bandwidth; configure and verify a single area. |
| 3.5 | connectivity-046–050 | Logical gateway, HSRP roles/tracking/preemption; study other FHRP implementations as appropriate. |
| 4.1 | services-001, services-nat-pool, services-003 | Static mapping, dynamic pool/rule/interfaces, exhaustion reasoning, end-to-end verification limits; configure NAT and interpret full tables/statistics. |
| 4.2 | services-004, services-ntp-status | Concrete isolated server/client configuration and selected-source/synchronization output; verify time accuracy and platform support in a lab. |
| 4.3 | services-006–007 | DHCP/DNS roles and name-resolution troubleshooting; inspect leases and actual DNS records. |
| 4.4 | services-snmp-security | Polling/notifications scenario directly compares SNMPv3 authPriv/authNoPriv/noAuthNoPriv and v2c; inspect actual management operations. |
| 4.5 | services-syslog-fields, services-010 | Decode Cisco facility/severity/mnemonic and evaluate logging thresholds; inspect full device messages and RFC PRI fields. |
| 4.6 | services-011–012 | Relay interface selection and DHCP-client command; configure and verify client/relay exchanges. |
| 4.7 | services-013–016 | Classification, marking, scheduling, shaping/policing, finite capacity; inspect PHB and congestion outcomes. |
| 4.8 | services-ssh-config, services-018 | Select a complete SSH change set from existing user/VTY/key configuration and diagnose reachability; configure complete server/authentication/VTY access and verify a new session. |
| 4.9 | services-019–020 | TFTP/FTP capabilities and transfer failure; perform transfers and inspect control/data filtering. |
| 5.1 | security-001–003 | Threat/vulnerability/exploit mapping, availability, mitigation; analyze varied incident scenarios. |
| 5.2 | security-004–005 | Awareness/reporting and physical controls; broader security-program study remains necessary. |
| 5.3 | security-006–007 | Configured user/VTY authentication mismatch and privileged secret; verify console, VTY, and EXEC access separately. |
| 5.4 | security-008–010 | Factor categories, certificates, individual credentials; study complexity, lifecycle, biometrics, and policy tradeoffs. |
| 5.5 | security-011–012 | Site-to-site versus remote access; study IPsec architecture and platform-specific VPN operation. |
| 5.6 | security-013–018 | Ordered ACL decisions, wildcard, direction, exception placement, type; configure/apply and verify counters/traffic. |
| 5.7 | security-019–020, security-dai-config, security-022–023 | Snooping trust configuration, bindings, DAI VLAN/trust configuration, static-host policy, port-security output; execute and verify all three features in a lab. |
| 5.8 | security-024, security-aaa-protocols | AAA function comparison plus conventional TACACS+/RADIUS transports, ports, and accounting evidence; configure and verify a supported AAA design. |
| 5.9 | security-wpa-versions, security-027–028 | Direct WPA/TKIP, WPA2/CCMP, WPA3/SAE comparison and Enterprise identity; examine version/client constraints. |
| 5.10 | security-wlan-auth, security-wlan-vlan | Representative GUI authentication and VLAN correction after successful authentication; configure and verify an actual WPA2 PSK WLAN. |
| 6.1 | automation-001–002 | Repeatability and operational validation; run a reviewed automation workflow. |
| 6.2 | automation-003, automation-controller-outage | Controller coordination and evidence-based retained-flow/table-miss behavior; compare architectures. |
| 6.3 | automation-005–009 | Planes, API directions, overlay/underlay; inspect a fabric and its transport dependencies. |
| 6.4 | automation-010–012 | Predictive/generative uses, ML alerts and false positives; evaluate data quality and operational context. |
| 6.5 | automation-crud-contract, automation-014–016 | Complete read/create/replace/delete method mapping, contracted PATCH, bearer transport, and response interpretation; exercise a real API and additional authentication schemes. |
| 6.6 | automation-ansible-task, automation-terraform-plan | Read an IOS configuration task and an in-place plan; distinguish proposed changes, application, operational verification, and state sensitivity. Execute supported examples and inspect repeat-run behavior. |
| 6.7 | automation-019–020 | JSON types and syntax; parse additional nested documents. |

## Specific gaps addressed by this revision

The direct samples added or replaced are Ethernet shared-medium behavior (1.3.b), IPv6 interface addressing/verification (1.8), IPv6 multicast (1.9.c), LLDP configuration (2.3), advanced WLAN central-switching interpretation (2.9), dynamic NAT pool association (4.1), NTP server/client setup and status interpretation (4.2), VTY local authentication (5.3), snooping/DAI configuration and port-security output (5.7), WPA/TKIP comparison (5.9), and representative WLAN GUI authentication/VLAN interpretation (5.10).

These additions improve the previously identified omissions. They do not turn the bank into a hands-on simulator or prove exhaustive assessment of every checklist subtopic. The page states that limitation, and topic references let learners inspect the supporting material.

## Remaining-gap follow-up

Eleven recognition questions were replaced with explicit new identities so old scores or review flags cannot attach to a substantially different assessment. This follow-up directly assesses private-range boundaries, IPv6 global-format/link-local scope, Windows subnet/gateway mismatch, Linux/macOS installed routes, MAC aging, SNMP security levels, Cisco syslog fields, conventional AAA protocol ports and accounting, complete CRUD method mapping, an Ansible IOS task, and a Terraform plan. Domain counts and parent-objective coverage remain unchanged.

Editorial checks use [RFC 1918 section 3](https://www.rfc-editor.org/rfc/rfc1918.html#section-3), [IPv6 addressing](https://www.rfc-editor.org/rfc/rfc4291.html), [Cisco MAC-table commands](https://www.cisco.com/c/en/us/td/docs/ios/lanswitch/command/reference/lsw_book/lsw_m1.html), [SNMPv3 user-based security](https://www.rfc-editor.org/rfc/rfc3414.html), [Cisco system-message format](https://www.cisco.com/c/en/us/td/docs/ios/system/messages/guide/consol_smg/sm_cnovr.html), [TACACS+](https://www.rfc-editor.org/rfc/rfc8907.html), [RADIUS](https://www.rfc-editor.org/rfc/rfc2865.html) and [accounting](https://www.rfc-editor.org/rfc/rfc2866.html), [HTTP methods](https://www.rfc-editor.org/rfc/rfc9110.html), [Ansible IOS configuration tasks](https://docs.ansible.com/projects/ansible/latest/collections/cisco/ios/ios_config_module.html), and [Terraform plan semantics](https://developer.hashicorp.com/terraform/cli/commands/plan). Added numeric tests independently compute private-block boundaries and the Windows subnet mismatch. The Linux/macOS excerpts, IOS snippets, and automation outputs are authored illustrations, not captured execution evidence. The Terraform resource type is explicitly a placeholder, not a claimed deployable provider configuration.

The remaining matrix items require broader study or execution on supported devices/tools. This repository review has not executed Cisco device configurations, Ansible against switches, or a Terraform provider. Those checks remain open; completing multiple-choice examples does not establish them.

## Identity and historical results

- Keep each question's explicit ID when moving it. Never reuse it for a different question.
- Choice text is the saved answer identity, so a different displayed position does not change its meaning.
- Revision fingerprints include the objective, prompt, correct answer, sorted choice set, evidence, and explanation. Meaningful edits retire selected/checked/first-check results for that question; the review flag remains.
- Revision fingerprints exclude source array ordering. Reordering a question or its distractors does not itself erase history.
- The original v1 bank's numeric answers cannot be safely mapped to this revised bank. The v2 loader carries review flags for continuing question IDs only and explains the reset. Replacement questions receive new semantic IDs, so flags for retired questions do not attach to a different topic. It leaves the old v1 storage record untouched. New attempts retain first-check results through retries/reloads.
- Choice permutation is stable by question ID/content and independent of ordinal position. It is not intended to conceal the openly published answer data; it removes the obvious UI pattern.

## Validation and future review

Tests verify unique prompts/IDs, independently specified domain counts and parent tags, available reference metadata, answer-position and option-length regression bounds, independent subnet/VLSM/IPv6/EUI-64/JSON calculations, revision semantics, legacy handling, UI feedback, and illustrative WLAN fields. The full frontend suite passes 72 tests, including 26 focused bank/persistence/page checks. The GitHub Pages production build passes. Structural and numeric tests do not establish originality, overall difficulty, or every device-specific explanation. Changes still need editorial review against primary references and relevant lab checks.

[Cisco's transition announcement](https://blogs.cisco.com/learning/stay-on-track-get-certified-before-the-ccna-refresh) lists February 2, 2027 as the last v1.1 testing day and February 3, 2027 as the v2.0 launch. The bank displays these dates and switches to a retired-blueprint notice on February 3. Before claiming v2.0 alignment, compare its published topics, revise this matrix and references, update question content, and rerun checks. Do not simply change the label.

## Editorial follow-up: October 2, 2026

The subsequent quality review corrected the guided subnet lab to use 192.0.2.97/27, a usable host in the next subnet, instead of its .96 network address. The wireless checkpoint and lab now explicitly use FlexConnect local switching with a local DHCP path. Its alternatives compare AP management, AP client transport, and controller transport mistakes.

Guided questions now order displayed choices using a stable question-ID/choice-text fingerprint. Authored indexes remain the saved answer identity, so existing selections and grading survive this display-only permutation. Source choice arrays must still not be reordered without migrating their stored indexes. Tests cover the old stored indexes, stable display ordering, answer identity, and absence of the three-lesson answer-position pattern.

The bank replaces services-017, access-039, and automation-004 with services-ssh-config, access-wlan-path, and automation-controller-outage. These new identities prevent old results or flags from attaching to materially different assessments. The new questions require selecting the full missing SSH change set, reconciling WLAN settings with controller/AP trunk evidence, and applying an explicit controller-outage policy. Domain counts remain unchanged. Security-awareness distractors now compare plausible controls, and discovery/fundamentals explanations address their actual alternatives.

Validation: all 76 frontend tests pass. This is targeted improvement of the reviewed weaknesses, not calibrated evidence of exam readiness or exhaustive practical coverage. Device configurations and the external labs still require execution on supported platforms.

Primary references for this follow-up: [Cisco IPv4 addressing](https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/ip-addressing/b-ip-addressing/m_config-ipv4-addr-0.html), [FlexConnect switching modes](https://www.cisco.com/c/en/us/td/docs/wireless/controller/8-10/config-guide/b_cg810/flexconnect.html), and [SSH configuration](https://www.cisco.com/c/en/us/td/docs/switches/lan/c9000/sec-crypto/ssh/secure-shell-configuration-guide/m-secure-shell.html).
