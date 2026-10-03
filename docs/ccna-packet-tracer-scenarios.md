# CCNA Packet Tracer scenarios

The `/practice/scenarios` page adds five original cases and 15 questions to the existing guided lessons and 200-question bank. Each case has predict, diagnose, and verify stages, answer explanations, a topology overview, and rebuild instructions. First-check results remain while the selected case is open; switching cases or reloading resets them.

## Capture provenance

All `.pkt` files and PNG captures under `ClientApp/public/labs/ccna` were created locally in Cisco Packet Tracer 9.0.1 on October 2, 2026. Screenshots are authentic, unaltered app-window captures. Question evidence is an authored, condensed study example; it is labeled separately from captured evidence. NAT example ports illustrate a collision and need not match the actual client ports. Device display names use the application's defaults; router CLI hostnames use R1/R2/R3.

Each folder contains `baseline.pkt`, `fault.pkt`, `repaired.pkt`, a topology capture, and captures of all three states. The routes and ACL prediction questions intentionally start from the failed state. Supporting captures show traffic or policy matches where useful.

| Case | Working baseline | Deliberate fault | Observed repair |
| --- | --- | --- | --- |
| VLAN trunk | PC-to-PC ping 4/4 | SW2 Fa0/2 allows only VLAN 10; ping 0/4 | Add VLAN 20, preserving 10; ping 4/4 and trunk lists 10,20 |
| OSPF | FULL and learned remote loopback route; repeated R2-to-R1 ping 5/5 | R2 hello 5 vs R1 hello 10, dead 40 on both; neighbor and route disappear after expiry | Default hello restored; FULL, remote routes, and 5/5 pings both directions after reopening the saved lab |
| Route selection | Exact destination lookup selects /24 through R2; repeated ping 4/4 | /32 through R3 at AD 200 wins; R3 deny gets matches, ping 0/4 | Remove /32; /24 selected through R2 and ping 4/4 |
| ACL order | Admin HTTPS page succeeds; Client request hits deny | Host permit moved below subnet deny; deny rises from 15 to 33 matches after both fresh requests | Admin HTTPS page returns; Client still hits deny; permit/deny counters rise, ICMP 4/4 |
| PAT | Both clients receive HTTP page; two translations share 203.0.113.5 | Outside role removed and translations cleared; new requests create zero translations | Outside role restored; both pages succeed and two new translations appear |

The ACL and route policies are deliberate restrictions in isolated teaching networks. They are retained during repair. Documentation address ranges remain within the simulated labs.

## Reproduction and limits

Open a saved lab with Packet Tracer 9.0.1, allow links, STP, ARP, and routing to converge, and repeat traffic tests. Saved NAT sessions and ACL counters should not be assumed to persist: generate fresh requests and compare counter changes. OSPF saved repair was reopened and both directions retested; all five baseline/fault/repair configurations were exercised in the app.

These are small teaching cases, not proof of complete CCNA objective coverage or validated exam readiness. Captured observations reflect Packet Tracer's simulated devices. The route case deliberately uses a policy on R3 to make the wrong next-hop choice observable, rather than implying that longest prefix matching alone causes packet loss.

## Maintenance

Content is in `ClientApp/src/content/ccnaScenarios.ts`; the page is in `ClientApp/src/pages/scenarios`. Paths honor Vite's configured base path for GitHub Pages deployment. Keep fault commands, question excerpts, screenshot provenance, and saved files aligned when revising a case. Re-run the device experiments after changing any networking premise.

## Publication policy check

Checked October 2, 2026. Local creation and verification do not establish permission to publish the Packet Tracer assets.

Cisco's [Packet Tracer Offer Description](https://www.cisco.com/c/dam/en_us/about/doing_business/legal/seula/cisco-packet-tracer-software.pdf), version 2.0 dated September 10, 2025, section 4.1, limits use to simulations connected with Networking Academy or purposes approved in writing. It expressly includes creation of courseware, videos, books, and other commercial or noncommercial uses among uses requiring prior written approval outside that scope. A standalone public study website appears to fall within that restriction; this is an interpretation of the published terms, not confirmation of permission.

Cisco's [copyright policy](https://www.cisco.com/c/en/us/about/brand-center/copyright-use.html) grants conditional permission for captures of public Cisco.com webpages. That exception does not explicitly cover Packet Tracer application captures. Attribution or a free website is not a substitute for the required permission.

Before public hosting of the Packet Tracer captures and lab files, establish the applicable Networking Academy authorization or obtain written approval covering this website and its assets. Original independent study text and original generic diagrams can be published separately, subject to ordinary copyright and trademark considerations. Never reproduce confidential actual exam questions or proprietary Cisco course material; see [Cisco exam policies](https://www.cisco.com/site/us/en/learn/training-certifications/exams/policies.html).
