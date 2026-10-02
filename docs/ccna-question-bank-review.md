# CCNA question bank review

Reviewed October 2, 2026, against commit `98edc01d02d88bb7b902c616a426b55ef61648ef`.

Implementation follow-up: the findings below describe the pre-fix bank. The revised bank removes the ordinal answer pattern, uses explicit question IDs and content revisions, retires incompatible answer history while retaining review flags, replaces distractors, adds the missing configuration/output and WLAN panel samples, and exposes topic references and version limits. See [the coverage and maintenance matrix](ccna-bank-coverage.md) for the current scope. The historical measurements and eight-test result below are baseline values, not current measurements.

## Verdict and scope

The 200-question bank is useful for introductory study. Manual inspection of every prompt, correct choice, distractor set, and explanation found no clear incorrect answer key. That does not establish exam readiness or independently prove original authorship. The biggest demonstrated problem is that answer positions are completely predictable. Coverage is broad at the parent-objective level but uneven in depth and incomplete at the subtopic level.

This review covers the six files in `src/TCP.Explorer/ClientApp/src/content/questionBank/`, their assembly and structural tests, and the question-bank page, saved progress, and page tests. It does not certify Cisco hardware behavior or assess actual exam items. No application code or question content was changed.

Cisco's [current exam page](https://www.cisco.com/site/us/en/learn/training-certifications/exams/ccna.html) identifies CCNA 200-301 v1.1. The [official v1.1 blueprint](https://learningcontent.cisco.com/documents/marketing/exam-topics/200-301-CCNA-v1.1.pdf) is the scope reference. Cisco has also [announced the transition](https://blogs.cisco.com/learning/stay-on-track-get-certified-before-the-ccna-refresh): v1.1 testing ends February 2, 2027, and v2.0 starts February 3, 2027. The bank's v1.1 label is appropriate today; it needs a version-review date as that transition approaches.

## Confirmed inventory

| Domain | Questions | Bank share | Blueprint share |
| --- | ---: | ---: | ---: |
| Network fundamentals | 40 | 20% | 20% |
| Network access | 40 | 20% | 20% |
| IP connectivity | 50 | 25% | 25% |
| IP services | 20 | 10% | 10% |
| Security fundamentals | 30 | 15% | 15% |
| Automation and programmability | 20 | 10% | 10% |

There are 200 distinct prompts and 200 distinct generated IDs. All 53 parent objective codes occur. There are 42 questions with a separate evidence block; the other 158 use their prompt as the scenario or ask a direct knowledge question. Authored style labels are 148 Apply, 20 Understand, and 32 Troubleshoot. These are author classifications, not calibrated difficulty measurements.

## Findings

### P1: Predictable answer positions undermine self-assessment

Location: `src/TCP.Explorer/ClientApp/src/content/questionBank/index.ts:12–18`.

The correct choice is authored first, and the array is rotated by `index % 4`. Every section therefore repeats **A, D, C, B**. Answer counts are A=51, B=49, C=49, D=51, but balanced totals do not remove the deterministic sequence.

A learner can select the correct answer for all 200 questions from the section-local question number alone. The page exposes that number through IDs such as `fundamentals-001`. Shuffle changes queue order but leaves choices and IDs intact, so it does not remove the shortcut.

Use a reproducible, nonsequential permutation tied to explicit question identity, or persist each session's choice order. Maintain saved responses by choice identity rather than display index when implementing this change. A regression check should demonstrate that section-local ordinals do not determine the answer position through the current four-step rule.

### P2: Parent-objective tags do not demonstrate complete skill coverage

Locations: `questionBank.test.ts:13–24`, `services.ts:4–8`, `fundamentals.ts:29–34`, `security.ts:29–33`, and `access.ts:41–43` within the question-bank folder.

The objective coverage test checks strings against a list generated from the bank's own domain metadata. It confirms parent-code presence. It does not independently compare requirements, test subobjective coverage, or measure whether the question assesses the required task.

Specific gaps observed against the blueprint:

| Area | What is tested | Missing direct assessment |
| --- | --- | --- |
| 1.3 | Fiber reach and fiber/copper comparison | Shared-medium versus point-to-point Ethernet behavior |
| 1.8 | IPv6 expansion and forwarding enable command | Address/prefix configuration and operational verification |
| 1.9 | Link-local scope, ULA prefix, anycast, modified EUI-64 | A question directly testing multicast behavior; multicast appears mainly in explanations or distractors |
| 2.3 | Discovery protocol identity, a CDP show command, absent LLDP neighbors | Concrete CDP/LLDP enable/disable configuration and interpreting realistic neighbor output |
| 2.9 | WLAN settings, enable state, general QoS purpose | Reading a supplied GUI configuration, including advanced settings |
| 4.1 | Static mapping command, pool exhaustion, end-to-end caution | Building a dynamic pool and binding the translation rule to it; interpreting a full verification example |
| 4.2 | Client source command and value of clock synchronization | Server operation and synchronization-output interpretation |
| 5.3 | Selecting local login and preferring enable secret | A complete local user/line configuration and access verification |
| 5.7 | Trust, bindings, DAI purpose, violation behavior | Concrete feature configuration and verification output |
| 5.9 | WPA2 lab choice, WPA3 SAE, Enterprise identity | Direct comparison involving original WPA/TKIP |
| 5.10 | PSK failure and Personal/Enterprise mismatch | Configuring or interpreting an actual or representative WLAN GUI |

For example, Cisco's [NTP verification guide](https://www.cisco.com/c/en/us/support/docs/technical-details/220303-verify-ntp-status-with-the-show-ntp-asso.html) shows how to distinguish configured peers from a selected synchronization source. Neither NTP question supplies that evidence. Cisco's [NAT configuration guide](https://www.cisco.com/c/en/us/support/docs/ip/network-address-translation-nat/13772-12.html) includes pool setup, translation-rule association, interface roles, and verification; the bank tests only parts of that workflow.

Retain the honest claim that all six domains and 53 parent codes are represented. Avoid interpreting that as full blueprint coverage. Add a separately maintained objective/subobjective matrix with an assessment type and a reviewable source for each entry. Supplement recognition questions with configuration and verification tasks.

### P2: Implausible distractors inflate apparent competence

Locations include `security.ts:4`, `automation.ts:12`, and `fundamentals.ts:11`.

Examples of incorrect options include an attacker being a subnet mask, an underlay being a browser CSS theme, and increasing a VLAN ID to power an AP. These are easy to eliminate without understanding the tested concept. Across the bank, 97 of 200 correct choices are uniquely longer than all three distractors. This is a wording bias measurement, not proof that every long answer is guessable.

Replace category errors with plausible misconceptions at the same technical level. For a security-concept question, use alternate mappings among threat, vulnerability, exploit, and mitigation. For an overlay question, use believable confusions between transport reachability, encapsulation, and segmentation. Keep option length and qualification reasonably comparable. Pilot questions before treating scores as evidence of proficiency.

### P2: Saved responses depend on ordinal and choice position

Locations: `questionBank/index.ts:16`, `pages/questionBank/bankProgress.ts:3–10,24–28`.

Question IDs are generated from array positions, and saved selections are numeric choice positions. There is no question-content revision check. Inserting, reordering, replacing a question, or changing its choice order can silently attach historical answers and first-check results to different content. This is a maintenance hazard, not evidence that today's saved scores are already corrupt. The README explicitly instructs maintainers to preserve ordering, which mitigates reordering but not edits in place.

Before revising the bank, give questions explicit immutable IDs and revision identifiers, store answer-choice identities, and invalidate or migrate affected historical attempts. Preserve existing first-check history only when it still refers to the same question and answer choices.

### P3: Structural tests cannot substantiate technical truth or originality

Location: `questionBank/questionBank.test.ts:3–31`.

The test named for original questions checks prompt and ID uniqueness. It cannot detect copied or paraphrased material. The explanation test accepts any text longer than 80 characters. The subnet test checks for expected strings in authored answers rather than independently calculating the results.

These checks are useful integrity checks, but their passing status must not be presented as factual or provenance certification. Rename the tests to describe what they verify. Add source references and review dates for technical content, with independent calculations for numeric questions where useful. Originality remains an authorship claim; this review found no evidence of copying and did not conduct a comprehensive plagiarism search.

## Technical checks and positive findings

The distinction between route installation and longest-prefix forwarding is correct, including the installed /24 with AD 200 beating a matching /16 with AD 110 for forwarding. This agrees with Cisco's [route-selection explanation](https://www.cisco.com/c/en/us/support/docs/ip/enhanced-interior-gateway-routing-protocol-eigrp/8651-21.pdf).

OSPF questions correctly distinguish local process IDs from router IDs, normal DROTHER 2-WAY relationships from full adjacency, election eligibility, and possible MTU-related exchange failures. The basic role/election statements agree with Cisco's [OSPF interface guide](https://www.cisco.com/c/en/us/support/docs/ip/open-shortest-path-first-ospf/13689-17.html). Platform assumptions are generally stated carefully rather than presented as universal laws.

ACL first-match behavior and implicit deny agree with Cisco's [IOS ACL overview](https://www.cisco.com/en/US/docs/ios-xml/ios/sec_data_acl/configuration/15-1mt/IP_Access_List_Overview.html). Root-guard behavior agrees with Cisco's [root guard guide](https://www.cisco.com/c/en/us/support/docs/lan-switching/spanning-tree-protocol/10588-74.html). The FlexConnect questions distinguish local and central switching consistently with Cisco's [wireless controller guide](https://www.cisco.com/c/en/us/td/docs/wireless/controller/8-10/config-guide/b_cg810/flexconnect.html). WPA3 SAE wording agrees with Cisco's [WPA3 guide](https://www.cisco.com/c/en/us/td/docs/wireless/controller/9800/17-16/config-guide/b_wl_17_16_cg/m_wpa3.html).

Independent calculations confirmed the /27 network/broadcast pair, /26 host-capacity requirement, nonoverlapping VLSM allocation, /26 host subnet separation, /20 host range, IPv6 expansion, modified EUI-64 result, and /26 membership used in longest-prefix matching. Valid JSON examples parsed successfully. IPv6 conceptual checks used [RFC 4291](https://www.rfc-editor.org/rfc/rfc4291.html).

The UI explicitly says these are practice questions rather than actual exam items. It records first-check correctness separately from current correctness, and a successful retry does not rewrite the first result. The page tests exercise that behavior across reloads. No pass guarantee, Cisco endorsement, or calibrated readiness score is claimed. Synthetic evidence should also be labeled illustrative on the bank page, as it already is in the guided-study documentation.

## Validation and recommended order

The existing bank and page suites passed: **2 files, 8 tests**. This supports the inspected UI and data behavior; it does not validate every explanation against a device lab. This was a source and content review, not a full application or hardware integration test.

1. Remove predictable answer positions while protecting saved history.
2. Address the concrete coverage gaps, especially NTP, NAT pools, IPv6 configuration, Layer 2 security, and WLAN GUI interpretation.
3. Replace implausible distractors and balance option wording.
4. Introduce question and answer identities plus content revisions before ongoing edits.
5. Add technical source/review metadata and describe automated tests accurately.
6. Keep the bank labeled v1.1 and schedule a content comparison before the February 2027 exam transition.

Suggested public description: “200 independently authored study questions mapped to the six CCNA 200-301 v1.1 domains. Includes explanations and saved practice results. Supplements configuration labs and official study material; results are not a validated prediction of exam performance.” Use “independently authored” only if the project owner can substantiate that provenance.
