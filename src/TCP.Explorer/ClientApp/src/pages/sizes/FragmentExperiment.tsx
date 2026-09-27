import { Link } from 'react-router';
import { GlossaryText } from '../../components/GlossaryText';
import { LayerTag } from '../../components/LayerTag';
import { Term } from '../../components/Term';
import { fixedIpHeader, fragment, type SizeInput, type SizeResult } from '../../model/packetModel';

const format = (value: number) => value.toLocaleString('en-US');
const maxShown = 7;

interface FragmentExperimentProps {
  input: SizeInput;
  result: SizeResult | null;
  dontFragment: boolean;
  onDontFragmentChange: (value: boolean) => void;
}

export function FragmentExperiment({ input, result, dontFragment, onDontFragmentChange }: FragmentExperimentProps) {
  return (
    <section className="fragment-pane" aria-labelledby="fragment-title">
      <h2 id="fragment-title" className="pane-title"><LayerTag layer="network" name={false} /> IPv4 fragmentation</h2>
      <div className="fragment-body">
        <p>What if one large IPv4 datagram reaches a smaller link? This separate example puts your application bytes plus one TCP header into a single IPv4 <Link className="inline-link" to="/concepts/datagram">datagram</Link>. Normal TCP should segment first. Here, compare IPv4 fragmentation with an oversized <Term id="df" /> packet.</p>
        <label className="check-label"><input type="checkbox" checked={dontFragment} onChange={event => onDontFragmentChange(event.target.checked)} /> <span>Set Don’t Fragment (<Term id="df" />)</span></label>
        <div aria-live="polite">
          {result ? <Fragments payload={input.dataSize + result.tcpHeader} mtu={result.effectiveMtu} dontFragment={dontFragment} /> : <p className="fragment-note">Enter valid values above to calculate fragments.</p>}
        </div>
        <p className="small-muted">Fragment experiment uses a 20-byte IPv4 header (no IP options). TCP options still apply. Only the first fragment starts with the TCP header; later fragments continue the original IP payload.</p>
      </div>
    </section>
  );
}

function Fragments({ payload, mtu, dontFragment }: { payload: number; mtu: number; dontFragment: boolean }) {
  const { blocked, pieces } = fragment(payload, mtu, dontFragment);
  if (blocked) {
    return (
      <div className="blocked">
        <strong>{format(payload + fixedIpHeader)} B exceeds {format(mtu)} B. <Term id="df" /> prevents fragmentation.</strong><br />
        <GlossaryText>A forwarding IPv4 router drops the packet and normally reports ICMP type 3/code 4 (subject to ICMP rules). In TCP.Core’s local send path, the MTU/DF check instead returns false. Blocked ICMP can cause path MTU black holes.</GlossaryText>
      </div>
    );
  }
  const truncated = pieces.length > maxShown;
  const shown = truncated ? [...pieces.slice(0, maxShown - 1), pieces.at(-1)!] : pieces;
  return (
    <>
      <div className="fragment-grid">
        {shown.map((piece, index) => (
          <div className="fragment-card" key={piece.offset}>
            <strong>{pieces.length === 1 ? 'One packet' : `Fragment ${truncated && index === maxShown - 1 ? pieces.length : index + 1}`}</strong>
            <span>{format(piece.total)} B total · {format(piece.bytes)} B payload</span>
            <span><Term id="fragment-offset">Offset</Term> {format(piece.offset)} · <Term id="mf" /> {piece.more ? '1' : '0'}</span>
          </div>
        ))}
      </div>
      <p className="fragment-note">
        {truncated && `${format(pieces.length)} fragments total; middle fragments omitted. `}
        <GlossaryText>{pieces.length === 1
          ? 'Fits the effective MTU; no fragmentation is needed, even with DF set.'
          : `Each fragment gets its own 20-byte IP header. Offsets use 8-byte units. Reassembly restores the original ${format(payload)}-byte IP payload before TCP can process it. Lose any one fragment and the whole datagram is lost; `}</GlossaryText>
        {pieces.length > 1 && <Link className="inline-link" to="/transmit?scenario=loss">watch it happen</Link>}
        {pieces.length > 1 && '.'}
      </p>
    </>
  );
}
