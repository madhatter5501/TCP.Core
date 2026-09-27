import { Link } from 'react-router';
import { PageHeading } from '../../components/PageHeading';
import { Term } from '../../components/Term';
import { useDocumentTitle } from '../../components/useDocumentTitle';

const comparison = [
  ['Setup', 'None; just send', 'Three-way handshake first'],
  ['Boundaries', 'Preserved: one send, one receive', 'None: bytes can split or merge across reads'],
  ['Loss / order', 'Application’s problem', 'Retransmitted and reordered by TCP'],
  ['State', 'Nothing between datagrams', 'Sequence numbers, windows, timers per connection'],
  ['Header cost', 'UDP: 8 B', 'TCP: 20–60 B'],
  ['Typical uses', 'DNS, DHCP, games, voice, QUIC', 'HTTP/1–2, SSH, SMTP, file transfer']
];

export function DatagramArticle() {
  useDocumentTitle('What is a datagram?');
  return (
    <>
      <PageHeading eyebrow="Concept · L3 & L4" title="What is a datagram?" next={{ to: '/layers/network', label: 'The network layer' }}>
        <p><strong>A self-contained unit of data that carries its own delivery address.</strong> The network handles each one independently: no connection is set up first, and nothing remembers the previous datagram. Think postcards, not a phone call: each names its destination, may take its own route, and can arrive late, out of order, twice, or never.</p>
      </PageHeading>

      <div className="concept-grid">
        <div className="concept-card">
          <h3>What a datagram promises</h3>
          <ul>
            <li><strong>Addressed.</strong> Each header names source and destination.</li>
            <li><strong>Bounded.</strong> It has a length. The receiver gets the whole datagram or nothing; one send is one receive.</li>
            <li><strong>Checked.</strong> A <Term id="checksum">checksum</Term> lets a receiver discard a damaged one.</li>
          </ul>
        </div>
        <div className="concept-card">
          <h3>What it does not promise</h3>
          <ul>
            <li><strong>Delivery.</strong> “Best effort” means a full queue or bad checksum simply drops it.</li>
            <li><strong>Order.</strong> Two datagrams can overtake each other.</li>
            <li><strong>Uniqueness or feedback.</strong> Duplicates happen, and the sender is not told about loss. <Term id="icmp" /> errors are occasional hints, not acknowledgments.</li>
          </ul>
        </div>
      </div>

      <div className="article-split">
        <div>
          <h2 className="article-heading">The word appears at two layers</h2>
          <p><strong>IP datagram (L3).</strong> RFC 791 calls IPv4’s unit a datagram; “packet” is the everyday synonym. Every TCP segment, UDP datagram, and ICMP message rides inside one.</p>
          <p><strong>UDP datagram (L4).</strong> UDP (RFC 768, the <em>User Datagram</em> Protocol) adds only ports, a length, and a checksum, so applications get IP’s datagram service almost unchanged.</p>
          <p><strong>TCP is the exception.</strong> It builds an ordered, reliable byte stream <em>on top of</em> unreliable IP datagrams. Its unit is called a segment, and segment boundaries are invisible to the application.</p>
        </div>

        <div className="nesting" aria-label="Encapsulation: an Ethernet frame contains an IP datagram, which contains a TCP segment, UDP datagram, or ICMP message">
          <div className="nest nest-link"><span>Ethernet frame</span>
            <div className="nest nest-ip"><span>IPv4 datagram</span>
              <div className="nest nest-l4"><span>TCP segment <em>or</em> UDP datagram <em>or</em> ICMP message</span>
                <div className="nest nest-app"><span>application data</span></div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="table-scroll">
        <table className="data-table">
          <thead><tr><th></th><th>Datagram service (IP, UDP)</th><th>Stream service (TCP)</th></tr></thead>
          <tbody>{comparison.map(([aspect, datagram, stream]) => <tr key={aspect}><td>{aspect}</td><td>{datagram}</td><td>{stream}</td></tr>)}</tbody>
        </table>
      </div>

      <div className="article-split">
        <div>
          <h2 className="article-heading">Datagram, packet, fragment</h2>
          <p>An IPv4 datagram can hold up to 65,535 bytes, but each link has an <Term id="mtu" />. When one is too large, IPv4 may split it into <strong>fragments</strong>. Each fragment travels as its own IP packet with a copy of the header, the same <Term id="identification">Identification</Term>, and an <Term id="fragment-offset">offset</Term>. The datagram exists again only after the receiver reassembles every piece.</p>
          <p>Lose one fragment and the whole datagram is lost. <Link className="inline-link" to="/transmit?scenario=loss">Try the “Drop one fragment” experiment</Link>, or <Link className="inline-link" to="/sizes">see the fragment math</Link>. That fragility is why TCP segments to fit the <Term id="mss" />, and why <Term id="df" /> exists.</p>
        </div>

        <div className="callout in-code">
          <strong>In the code</strong>
          <p><code>IPv4Host.SendIPv4</code> sends one datagram; <code>Fragmentation/IPv4Fragmenter</code> splits it and <code>Fragmentation/IPv4Reassembler</code> rebuilds it before <code>IPv4ProtocolDispatcher</code> hands the payload to TCP or ICMP. UDP is not implemented yet, so today TCP.Core’s datagrams are IP datagrams only.</p>
        </div>
      </div>
    </>
  );
}
