import { PageHeading } from '../../components/PageHeading';
import { useDocumentTitle } from '../../components/useDocumentTitle';
import './troubleshooting.css';

const sources = [
  ['C# background services', 'https://learn.microsoft.com/en-us/aspnet/core/fundamentals/host/hosted-services?view=aspnetcore-10.0'],
  ['Prometheus SNMP exporter', 'https://github.com/prometheus/snmp_exporter'],
  ['Prometheus blackbox exporter', 'https://github.com/prometheus/blackbox_exporter'],
  ['Prometheus target discovery', 'https://prometheus.io/docs/guides/file-sd/'],
  ['Prometheus alerting', 'https://prometheus.io/docs/alerting/latest/overview/'],
  ['LLDP topology discovery', 'https://www.cisco.com/c/en/us/td/docs/ios/cether/configuration/guide/ce_lldp-med.pdf'],
  ['NetFlow / IPFIX conversation metadata', 'https://netascode.cisco.com/docs/data_models/iosxe/device/flow/'],
  ['SPAN / RSPAN / ERSPAN', 'https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst6500/ios/15-3SY/config_guide/sup2T/15_2_sy_swcg_2T/span_rspan_erspan.html'],
  ['Cisco embedded packet capture', 'https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/ntw-servs/b-network-services/m_nm-packet-capture-xe.html'],
  ['Dumpcap filters, limits, and rolling files', 'https://www.wireshark.org/docs/man-pages/dumpcap.html'],
  ['TLS decryption requirements', 'https://wiki.wireshark.org/TLS/']
];

export function TroubleshootingPage() {
  useDocumentTitle('Troubleshooting Ideas');
  return <div className="troubleshooting-page">
    <PageHeading eyebrow="Design a NetDevOps exercise" title="Troubleshooting Ideas" next={{ to: '/transmit', label: 'Inspect a transmission' }}>
      <p>From “the lab cannot print” to a network map, location-specific checks, and evidence you can inspect.</p>
    </PageHeading>
    <div className="callout">
      <strong>Exercise brief · proposed system</strong>
      <p>Design a C# tool that inventories devices on a schedule, maps their connections, monitors health with Prometheus, and coordinates packet captures when a test fails. This page is a design exercise; it does not scan your network, collect telemetry, or start captures.</p>
    </div>
    <nav className="troubleshooting-index" aria-label="Exercise sections">
      <a className="inline-link" href="#problem">The incident</a>
      <a className="inline-link" href="#architecture">The system</a>
      <a className="inline-link" href="#evidence">Choose evidence</a>
      <a className="inline-link" href="#investigate">Investigate</a>
      <a className="inline-link" href="#captures">Automate captures</a>
      <a className="inline-link" href="#build">Build it in stages</a>
    </nav>

    <section id="problem" className="panel troubleshooting-section">
      <div className="eyebrow">01 · Start with a question</div>
      <h2>Floor 2, lab room 1 cannot access the print server on floor 4</h2>
      <p>Other rooms can print. Is the problem DNS, the lab’s network path, a forwarding policy, the server’s service, or the printing application? Collect evidence before deciding.</p>
      <figure className="troubleshooting-path">
        <ol aria-label="Illustrative path to the print server">
          <li><strong>Lab room 1</strong><span>Floor 2 · client + probe</span></li>
          <li><strong>Access switch</strong><span>Lab VLAN and uplink</span></li>
          <li><strong>Routing / policy</strong><span>Path between VLANs</span></li>
          <li><strong>Print server</strong><span>Floor 4 · server + probe</span></li>
        </ol>
        <figcaption>Illustrative topology, not a discovered network. Put a probe in the lab’s VLAN; a successful test from the monitoring server alone does not establish reachability from the lab. A nearby probe still may not reproduce one PC’s host firewall, identity, or application settings.</figcaption>
      </figure>
      <p><strong>Exercise outcome:</strong> explain what failed, where your evidence was collected, what remains uncertain, and which test verifies recovery.</p>
    </section>

    <section id="architecture" className="panel troubleshooting-section">
      <div className="eyebrow">02 · Give each component a job</div>
      <h2>Inventory on a timer. Draw the map when you need it.</h2>
      <p>The background work continues while the map is closed. Opening the canvas reads stored devices and connections, then overlays recent health and alerts. Clicking a device or link opens its history, charts, and related incidents.</p>
      <div className="table-scroll"><table className="data-table">
        <thead><tr><th scope="col">Component</th><th scope="col">Responsibility</th></tr></thead>
        <tbody>
          <tr><td>C# worker + API</td><td>Use a BackgroundService with a scheduled loop to discover devices, collect topology, and run read-only audits. Use timeouts, cancellation, bounded concurrency, and prevent overlapping collection runs.</td></tr>
          <tr><td>Inventory database</td><td>Store stable device identities, addresses, interfaces, observed connections, first/last-seen times, and change history. Keep expected configuration separate from observed state.</td></tr>
          <tr><td>Prometheus + exporters</td><td>Scrape time-series metrics through SNMP and host exporters; use blackbox probes for reachability and service checks. Let the inventory publish targets through file-based or HTTP discovery.</td></tr>
          <tr><td>Alertmanager</td><td>Group, silence, and route alerts produced by Prometheus rules. A webhook can notify the C# incident service to coordinate approved capture points.</td></tr>
          <tr><td>Map and incident view</td><td>Display observed connections, link health, the affected location, timestamps, and evidence. Preserve manual layout positions so each inventory update does not rearrange the map.</td></tr>
          <tr><td>Optional flow collector</td><td>Receive NetFlow/IPFIX for conversations and top talkers. Store detailed flow records separately from Prometheus; expose bounded aggregate metrics where useful.</td></tr>
        </tbody>
      </table></div>
      <h3>Discovery is not the same as topology</h3>
      <p>A ping sweep finds some reachable addresses; it does not reveal physical connections or all devices. Query managed equipment for LLDP/CDP neighbors and interface information, supplement with MAC and ARP tables, and allow manual links when needed. Mark links as observed, inferred, or manual, with their source and timestamp. An unanswered ping means “no reply,” not necessarily “device absent.”</p>
      <p>As suggested starting intervals, refresh inventory every 5–15 minutes and scrape health every 15–60 seconds, then tune to the equipment and scale. Report stale or failed collection explicitly. A configuration audit could compare expected VLAN membership or interface settings with observed values and record drift without changing the device.</p>
    </section>

    <section id="evidence" className="panel troubleshooting-section">
      <div className="eyebrow">03 · Know what each observation means</div>
      <h2>Can device telemetry replace Wireshark?</h2>
      <p>It can answer many everyday monitoring questions without opening a packet analyzer. It does not provide the same inspection as captured packets.</p>
      <div className="table-scroll"><table className="data-table">
        <thead><tr><th scope="col">Evidence</th><th scope="col">Useful questions</th><th scope="col">Limit</th></tr></thead>
        <tbody>
          <tr><td>Interface / device metrics</td><td>Is the link up? How busy is it? Are errors or discards increasing? Is the device overloaded?</td><td>Counters summarize activity; they do not show a specific request or its contents. Available metrics vary by device.</td></tr>
          <tr><td>Active probes</td><td>Can this location resolve the server name and reach the required service? How long does the check take?</td><td>A timeout identifies a failed test, not its cause. Ping success does not prove printing works.</td></tr>
          <tr><td>NetFlow / IPFIX</td><td>Which endpoints communicate, on which ports, and how much? Who are the top talkers?</td><td>Conversation metadata generally lacks packet payloads; sampling and export delays can limit detail.</td></tr>
          <tr><td>Logs and policy counters</td><td>Did a rule match? Did a link flap? Did the application report an error?</td><td>Match the time and scope: a shared ACL counter increasing does not identify your test by itself.</td></tr>
          <tr><td>Packet capture</td><td>Was a connection request sent? Did a response return? What DNS answer or TCP behavior was observed?</td><td>Only sees traffic at the capture point. TLS contents remain encrypted unless appropriate decryption secrets are available.</td></tr>
        </tbody>
      </table></div>
      <p>Built-in capability usually still needs configuration: SNMP credentials, flow export destinations, neighbor discovery, and access to management interfaces. Consumer and unmanaged equipment may expose little. Prefer SNMPv3 where supported and keep credentials in the backend.</p>
    </section>

    <section id="investigate" className="panel troubleshooting-section">
      <div className="eyebrow">04 · Work the incident</div>
      <h2>Test from the affected location</h2>
      <ol className="troubleshooting-steps">
        <li><strong>Confirm scope.</strong> Does this affect one PC, the entire lab, or other floors? Record the client, destination, time, and actual printing service/protocol in use.</li>
        <li><strong>Test name resolution.</strong> Resolve the print server’s name from the lab and compare the answer with a working location. A wrong address and a DNS timeout call for different follow-up tests.</li>
        <li><strong>Test the required service.</strong> Probe the configured service from the lab and floor 4. Choose the protocol the environment actually uses; do not assume one TCP port represents every printing setup.</li>
        <li><strong>Correlate the path.</strong> Check lab switch ports, VLAN membership, uplinks, routes, applicable policies, and server logs. Use timestamps and recent changes; a green link does not establish application reachability.</li>
        <li><strong>Capture and repeat.</strong> Start a filtered capture at the affected client and server, then repeat the failed connection. Add an intermediate capture point if needed to narrow the unexplained portion of the path.</li>
        <li><strong>Verify recovery.</strong> Repeat the same checks from the lab after repair, then submit a controlled print job. Establishing a connection alone does not prove the job completes.</li>
      </ol>
      <div className="callout"><strong>Example incident summary · illustrative</strong><p>Lab 1 → print service: connection timeout. DNS resolved to the expected address. Floor 4 service probe succeeded. Lab failure observed on three consecutive checks. Cause not yet established; endpoint captures requested.</p></div>
      <details className="disclosure"><summary>Checkpoint: what can you conclude from those results?</summary><div className="disclosure-body">
        <p>The service is reachable from the floor 4 probe but failed from the lab probe. Investigate the location-specific path and client differences. You cannot yet conclude that an ACL caused the failure or that the server is healthy for every client.</p>
        <p>If the client capture shows a SYN and the server capture does not, investigate between those observation points. If the server sees the SYN but emits no response, inspect server-side behavior. If it emits a response that the client does not see, investigate the return path. Check capture filters, interfaces, packet drops, and timing before treating an absent packet as proof of loss. NAT can change the addresses used to correlate captures.</p>
      </div></details>
    </section>

    <section id="captures" className="panel troubleshooting-section">
      <div className="eyebrow">05 · Capture when it matters</div>
      <h2>Automate captures without a tap at every hop</h2>
      <p>You need observation points that can see the relevant traffic. A monitoring computer on an ordinary switched port cannot simply see every other port’s traffic.</p>
      <div className="table-scroll"><table className="data-table">
        <thead><tr><th scope="col">Method</th><th scope="col">Where it sees traffic</th><th scope="col">Setup</th></tr></thead>
        <tbody>
          <tr><td>Endpoint agent</td><td>Traffic visible on the affected client or server interface.</td><td>Install a capture tool such as dumpcap and provide the required capture privileges.</td></tr>
          <tr><td>SPAN / port mirroring</td><td>Copies selected switch ports or VLANs to a capture interface.</td><td>Configure the switch and connect a collector to its mirror destination.</td></tr>
          <tr><td>ERSPAN</td><td>Sends mirrored packets over the network to a remote collector.</td><td>Requires compatible equipment and a collector that understands the encapsulation; budget transport bandwidth.</td></tr>
          <tr><td>Embedded device capture</td><td>Selected traffic at supported switch/router capture points.</td><td>Check model, software, forwarding-path support, and capture limits; export the resulting PCAP.</td></tr>
          <tr><td>Physical tap</td><td>Traffic on the installed link.</td><td>Useful where independent link observation is needed; choose hardware suitable for the link.</td></tr>
        </tbody>
      </table></div>
      <h3>An example trigger workflow</h3>
      <ol className="troubleshooting-steps">
        <li>A location-specific service check fails repeatedly. Prometheus fires an alert after a configured duration; Alertmanager sends the incident webhook.</li>
        <li>The C# coordinator creates one incident, chooses available capture points, and applies a filter for the affected endpoints and service. Repeated notifications reuse the incident rather than starting unlimited captures.</li>
        <li>Start captures, wait for confirmation, and repeat the test. A suggested initial capture window is 30 seconds with an explicit size limit.</li>
        <li>Stop and retrieve the files. Record capture point, interface, filter, start/end times, clock synchronization status, and any reported capture drops or failures.</li>
        <li>Attach PCAP/PCAPNG files and probe results to the incident. Summarize observable behavior with a packet analyzer such as TShark; offer the files for deeper inspection in Wireshark.</li>
      </ol>
      <h3>The trigger cannot capture the past</h3>
      <p>A capture started after an alert misses packets that already passed. Either reproduce the failure while capturing or maintain a bounded rolling capture at selected observation points. Dumpcap supports rotating files by time or size. When triggered, preserve completed recent files before rotation overwrites them and retain a short post-trigger window.</p>
      <p>Start with endpoint captures and add intermediate points as needed. Mirroring and captures can miss packets or consume device resources; check capacity and capture-drop statistics. Keep filters narrow, cap duration/storage/concurrency, restrict access to captures, and expire old files. Capture only on networks and devices you administer or are authorized to inspect.</p>
      <details className="disclosure"><summary>Checkpoint: why is a tap at every hop unnecessary?</summary><div className="disclosure-body">
        <p>Endpoint captures establish what left the client and what arrived at the server. Device captures or mirrored ports can then narrow an unexplained gap. A tap is one observation method, not a prerequisite for automation. Two endpoint captures locate a gap between endpoints; they do not identify the exact intermediate hop without further evidence.</p>
      </div></details>
    </section>

    <section id="build" className="panel troubleshooting-section">
      <div className="eyebrow">06 · Make it demonstrable</div>
      <h2>Build one small network before expanding</h2>
      <ol className="troubleshooting-steps">
        <li><strong>Inventory and map.</strong> Use one managed switch, a router, and a few hosts. Schedule read-only collection, persist identities and connections, and show freshness and evidence source on a clickable map.</li>
        <li><strong>Metrics and checks.</strong> Add Prometheus exporters, interface throughput/error charts, and a probe on each side of the test path. Publish discovered targets from the inventory.</li>
        <li><strong>Incidents and history.</strong> Add an outage alert, maintenance silences, and an incident timeline. Record configuration drift separately from service failures.</li>
        <li><strong>Triggered evidence.</strong> Integrate one endpoint capture agent, then a second endpoint. Demonstrate filtering, automatic stopping, file retrieval, and duplicate-trigger handling before adding device captures.</li>
        <li><strong>Broader visibility.</strong> Add flow collection, rolling captures, additional vendors, and more detailed audits as the lab warrants them.</li>
      </ol>
      <h3>Deliverables for this exercise</h3>
      <ul>
        <li>An architecture sketch and inventory schema with device, interface, connection, observation, and incident records.</li>
        <li>A documented test matrix: working baseline, deliberate DNS/path/service failures, expected observations, and recovery checks.</li>
        <li>A demonstration that detects a lab-to-server failure, records its evidence, and verifies the repair without claiming more than the observations establish.</li>
        <li>Tests for collection timeouts, stale inventory, counter resets, repeated alerts, unavailable capture agents, and capture size/time limits.</li>
      </ul>
      <p>This creates concrete NetDevOps work to discuss: scheduled collection, network protocols, data modeling, monitoring rules, troubleshooting, and repeatable verification. Keep the collector and credentials on a trusted backend. GitHub Pages can host this exercise or a sanitized demonstration, but it cannot run a C# worker or directly poll your private network.</p>
    </section>

    <section className="panel troubleshooting-section" aria-labelledby="troubleshooting-sources">
      <h2 id="troubleshooting-sources">Read the implementation references</h2>
      <p>Primary documentation reviewed October 2, 2026. Confirm capabilities against the exact devices and software you use.</p>
      <ul className="troubleshooting-sources">{sources.map(([label, url]) => <li key={url}><a className="inline-link" href={url} target="_blank" rel="noreferrer">{label}</a></li>)}</ul>
    </section>
  </div>;
}
