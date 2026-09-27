import { Link } from 'react-router';
import { layers } from '../../content/layers';
import { PageHeading } from '../../components/PageHeading';
import { useDocumentTitle } from '../../components/useDocumentTitle';

export function PduNamesArticle() {
  useDocumentTitle('PDU names');
  return (
    <>
      <PageHeading eyebrow="Keep the names straight" title="One payload. A different PDU at each layer." next={{ to: '/concepts/datagram', label: 'What is a datagram?' }}>
        <p>A PDU (protocol data unit) is what one layer hands to the layer below, including that layer’s own header. The bytes of your message stay the same; the name changes with every wrapper.</p>
      </PageHeading>
      <div className="table-scroll">
        <table className="data-table pdu-table">
          <thead><tr><th>Layer</th><th>PDU</th><th>Address / identifier</th><th>What it adds</th><th>TCP.Core today</th></tr></thead>
          <tbody>
            {layers.map(layer => (
              <tr key={layer.slug}>
                <td><Link className="pdu-layer" to={`/layers/${layer.slug}`} style={{ color: layer.color }}>{layer.number} · {layer.name}</Link></td>
                <td>{layer.pdu}</td><td>{layer.address}</td><td>{layer.adds}</td><td>{layer.scope}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="article-notes">
        <p><strong>Five-layer teaching model.</strong> L5–7 groups the OSI session, presentation, and application layers. The four-layer TCP/IP model combines link and physical. ICMP belongs alongside IPv4 at L3; ARP connects IPv4 next hops to L2 addresses.</p>
        <p><strong>Why “datagram” appears twice.</strong> Both IP and UDP call their unit a datagram, because both offer the same kind of service. <Link className="inline-link" to="/concepts/datagram">Read what that means</Link>.</p>
      </div>
    </>
  );
}
