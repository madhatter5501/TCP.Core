export const bankReviewDate = '2026-10-02';
export const blueprintUrl = 'https://learningcontent.cisco.com/documents/marketing/exam-topics/200-301-CCNA-v1.1.pdf';
export const examTransitionUrl = 'https://blogs.cisco.com/learning/stay-on-track-get-certified-before-the-ccna-refresh';

// A separately transcribed parent checklist, not generated from bank counts/tags.
// Presence means a study sample exists, not that a learner has demonstrated the skill.
export const blueprintObjectives = [
  '1.1', '1.2', '1.3', '1.4', '1.5', '1.6', '1.7', '1.8', '1.9', '1.10', '1.11', '1.12', '1.13',
  '2.1', '2.2', '2.3', '2.4', '2.5', '2.6', '2.7', '2.8', '2.9',
  '3.1', '3.2', '3.3', '3.4', '3.5',
  '4.1', '4.2', '4.3', '4.4', '4.5', '4.6', '4.7', '4.8', '4.9',
  '5.1', '5.2', '5.3', '5.4', '5.5', '5.6', '5.7', '5.8', '5.9', '5.10',
  '6.1', '6.2', '6.3', '6.4', '6.5', '6.6', '6.7'
] as const;

export interface TopicReference { title: string; url: string }
const cisco = (title: string, path: string): TopicReference => ({ title, url: `https://www.cisco.com/${path}` });
const rfc = (number: number, title: string): TopicReference => ({ title: `RFC ${number}: ${title}`, url: `https://www.rfc-editor.org/rfc/rfc${number}.html` });
const campus = cisco('Cisco campus LAN and WLAN design', 'c/en/us/td/docs/solutions/CVD/Campus/cisco-campus-lan-wlan-design-guide.html');
const wireless = cisco('Cisco FlexConnect configuration', 'c/en/us/td/docs/wireless/controller/8-10/config-guide/b_cg810/flexconnect.html');
const ipv6 = cisco('Cisco IPv6 addressing and verification', 'c/en/us/td/docs/ios/ipv6/configuration/guide/ipv6-xe-16-book-cat8000/m_ip6-addrg-bsc-con.html');
const routes = cisco('Cisco route selection', 'c/en/us/support/docs/ip/enhanced-interior-gateway-routing-protocol-eigrp/8651-21.pdf');
const ospf = cisco('Cisco OSPF interface operation', 'c/en/us/support/docs/ip/open-shortest-path-first-ospf/13689-17.html');
const ssh = cisco('Cisco SSH configuration', 'c/en/us/td/docs/switches/lan/c9000/sec-crypto/ssh/secure-shell-configuration-guide/m-secure-shell.html');
const dai = cisco('Cisco DAI and DHCP binding verification', 'c/en/us/td/docs/switches/lan/catalyst3650/software/release/16-12/configuration_guide/sec/b_1612_sec_3650_cg/configuring_dynamic_arp_inspection.html');
const wpa2 = cisco('Cisco WPA2 configuration example', 'c/en/us/support/docs/wireless-mobility/wireless-lan-wlan/67134-wpa2-config.html');
const wpa3 = cisco('Cisco WPA3 and SAE', 'c/en/us/td/docs/wireless/controller/9800/17-16/config-guide/b_wl_17_16_cg/m_wpa3.html');

// Topic-level reading links. They are references, not Cisco endorsement or proof
// that a multiple-choice result validates configuration skill.
const references: Record<string, TopicReference[]> = {
  '1.1': [campus], '1.2': [campus], '1.3': [campus], '1.4': [campus],
  '1.5': [rfc(9293, 'TCP'), rfc(768, 'UDP')],
  '1.6': [rfc(4632, 'Classless addressing')], '1.7': [rfc(1918, 'Private addressing')],
  '1.8': [ipv6], '1.9': [rfc(4291, 'IPv6 addressing'), rfc(4193, 'Unique local IPv6 addresses')],
  '1.10': [{ title: 'Microsoft ipconfig reference', url: 'https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/ipconfig' }],
  '1.11': [campus, wpa2],
  '1.12': [{ title: 'Docker containers and virtual machines', url: 'https://docs.docker.com/get-started/docker-concepts/the-basics/what-is-a-container/' }],
  '1.13': [campus],
  '2.1': [campus], '2.2': [campus],
  '2.3': [cisco('Cisco LLDP configuration', 'c/en/us/td/docs/switches/lan/c9000/lyr2-fwd/cdp-lldp-mac-udld/cdp-lldp-mac-udld-configuration-guide/configure-lldp.html')],
  '2.4': [cisco('Cisco EtherChannel configuration', 'c/en/us/td/docs/switches/lan/c9000/lyr2-fwd/etherchannel/etherchannel-configuration-guide/etherchannels.html')],
  '2.5': [cisco('Cisco root guard', 'c/en/us/support/docs/lan-switching/spanning-tree-protocol/10588-74.html'), campus],
  '2.6': [wireless], '2.7': [wireless], '2.8': [ssh, campus],
  '2.9': [cisco('Cisco policy profiles and local switching GUI', 'c/en/us/td/docs/wireless/controller/9800/17-7/config-guide/b_wl_17_7_cg/m_vewlc_flex_connect.html'), wpa2],
  '3.1': [routes], '3.2': [routes], '3.3': [routes, ipv6], '3.4': [ospf], '3.5': [campus],
  '4.1': [cisco('Cisco NAT configuration and verification', 'c/en/us/support/docs/ip/network-address-translation-nat/13772-12.html')],
  '4.2': [cisco('Cisco NTP status and associations', 'c/en/us/support/docs/technical-details/220303-verify-ntp-status-with-the-show-ntp-asso.html')],
  '4.3': [rfc(2131, 'DHCP'), rfc(1034, 'DNS concepts')],
  '4.4': [rfc(3411, 'SNMP architecture')], '4.5': [rfc(5424, 'Syslog')], '4.6': [rfc(2131, 'DHCP')],
  '4.7': [rfc(2475, 'Differentiated services')], '4.8': [ssh], '4.9': [rfc(1350, 'TFTP'), rfc(959, 'FTP')],
  '5.1': [rfc(4949, 'Security glossary')], '5.2': [rfc(4949, 'Security glossary')], '5.3': [ssh],
  '5.4': [rfc(5280, 'Certificates'), rfc(4949, 'Security glossary')], '5.5': [rfc(4301, 'IPsec architecture')],
  '5.6': [cisco('Cisco IOS ACL behavior', 'en/US/docs/ios-xml/ios/sec_data_acl/configuration/15-1mt/IP_Access_List_Overview.html')],
  '5.7': [dai, cisco('Cisco port security', 'c/en/us/td/docs/routers/7600/ios/15S/configuration/guide/7600_15_0s_book/port_sec.pdf')],
  '5.8': [rfc(8907, 'TACACS+'), rfc(2865, 'RADIUS')], '5.9': [wpa2, wpa3], '5.10': [wpa2],
  '6.1': [{ title: 'Ansible playbooks', url: 'https://docs.ansible.com/projects/ansible/latest/playbook_guide/playbooks_intro.html' }],
  '6.2': [campus], '6.3': [campus],
  '6.4': [{ title: 'Cisco AI and machine learning in CCNA v1.1', url: 'https://blogs.cisco.com/learning/understanding-the-updated-ccna-v1-1-with-ai-machine-learning-and-more' }],
  '6.5': [rfc(9110, 'HTTP semantics'), rfc(5789, 'HTTP PATCH'), rfc(6750, 'Bearer tokens')],
  '6.6': [{ title: 'Ansible playbooks', url: 'https://docs.ansible.com/projects/ansible/latest/playbook_guide/playbooks_intro.html' }, { title: 'Terraform plans', url: 'https://developer.hashicorp.com/terraform/cli/commands/plan' }, { title: 'Terraform sensitive data', url: 'https://developer.hashicorp.com/terraform/language/manage-sensitive-data' }],
  '6.7': [rfc(8259, 'JSON')]
};
export function topicReferences(objective: string): TopicReference[] {
  return references[objective] ?? [];
}

export function blueprintStatus(date = new Date()): string {
  return date.toISOString().slice(0, 10) >= '2027-02-03'
    ? 'This bank targets the retired CCNA v1.1 blueprint. Compare with the current Cisco exam topics before using it for exam preparation.'
    : 'Targets CCNA v1.1. Cisco lists February 2, 2027 as its last testing day; v2.0 begins February 3, 2027.';
}
