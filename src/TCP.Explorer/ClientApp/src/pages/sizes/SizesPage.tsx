import { useState } from 'react';
import { Link } from 'react-router';
import { PageHeading } from '../../components/PageHeading';
import { useDocumentTitle } from '../../components/useDocumentTitle';
import type { LayerSlug } from '../../content/layers';
import { GlossaryText } from '../../components/GlossaryText';
import { LayerTag } from '../../components/LayerTag';
import { Term } from '../../components/Term';
import { calculate, defaultSizeInput, fcsBytes, type SizeInput, type SizeResult } from '../../model/packetModel';
import { FragmentExperiment } from './FragmentExperiment';
import './sizes.css';

const format = (value: number) => value.toLocaleString('en-US');

/** Byte-breakdown labels that have a glossary entry. */
const byteKeyTerms: Record<string, string> = { ETH: 'ethernet-frame', IP: 'ipv4', TCP: 'segment', Pad: 'padding', FCS: 'fcs' };
/** Which layer adds each part of the frame. */
const byteKeyLayers: Record<string, LayerSlug> = { ETH: 'link', IP: 'network', TCP: 'transport', Data: 'application', Pad: 'link', FCS: 'link' };
const mtuPresets = [['Ethernet', 1500], ['PPPoE', 1492], ['Jumbo', 9000]] as const;

/** Number inputs keep their raw text so a half-typed value stays editable; the model rejects invalid numbers. */
type Draft = Record<'mtu' | 'pathMtu' | 'peerMss' | 'dataSize', string> & Pick<SizeInput, 'ipOptions' | 'tcpOptions' | 'vlan'>;

const toDraft = (input: SizeInput): Draft => ({
  mtu: String(input.mtu), pathMtu: String(input.pathMtu), peerMss: String(input.peerMss), dataSize: String(input.dataSize),
  ipOptions: input.ipOptions, tcpOptions: input.tcpOptions, vlan: input.vlan
});

const parse = (text: string) => (text.trim() === '' ? NaN : Number(text));

export function SizesPage() {
  useDocumentTitle('MTU & MSS lab');
  const [draft, setDraft] = useState(() => toDraft(defaultSizeInput));
  const [dontFragment, setDontFragment] = useState(false);
  const input: SizeInput = { ...draft, mtu: parse(draft.mtu), pathMtu: parse(draft.pathMtu), peerMss: parse(draft.peerMss), dataSize: parse(draft.dataSize) };
  let result: SizeResult | null = null;
  let error = '';
  try { result = calculate(input); } catch (caught) { error = (caught as Error).message; }
  const set = <K extends keyof Draft>(key: K, value: Draft[K]) => setDraft(current => ({ ...current, [key]: value }));

  return (
    <>
      <PageHeading eyebrow="Experiment · The size of things" title="Small headers. Real consequences." next={{ to: '/concepts/datagram', label: 'What is a datagram?' }}>
        <p>Change the limits and see how an IPv4/TCP transfer fits: what each header costs, how many segments you need, and what happens when a datagram is too big for the link.</p>
      </PageHeading>
      <div className="sizes-bench fill">
        <div className="lab-inputs">
          <label htmlFor="mtu">Outgoing link MTU <span>bytes</span></label>
          <input id="mtu" type="number" min={68} max={9000} step={1} value={draft.mtu} onChange={event => set('mtu', event.target.value)} />
          <div className="presets" aria-label="MTU examples">
            {mtuPresets.map(([name, value]) => (
              <button key={name} type="button" onClick={() => setDraft(current => ({ ...current, mtu: String(value), pathMtu: String(value) }))}>{name} {value}</button>
            ))}
          </div>
          <div className="input-pair">
            <div>
              <label htmlFor="path-mtu">Path MTU <span>bytes</span></label>
              <input id="path-mtu" type="number" min={68} max={9000} value={draft.pathMtu} onChange={event => set('pathMtu', event.target.value)} />
            </div>
            <div>
              <label htmlFor="peer-mss">Peer’s MSS <span>bytes</span></label>
              <input id="peer-mss" type="number" min={1} max={65495} value={draft.peerMss} onChange={event => set('peerMss', event.target.value)} />
            </div>
          </div>
          <div className="input-pair">
            <div>
              <label htmlFor="ip-options">IPv4 options</label>
              <select id="ip-options" value={draft.ipOptions} onChange={event => set('ipOptions', Number(event.target.value))}>
                <option value={0}>None · 0 B</option><option value={4}>4 bytes</option><option value={12}>12 bytes</option><option value={40}>40 bytes</option>
              </select>
            </div>
            <div>
              <label htmlFor="tcp-options">TCP options</label>
              <select id="tcp-options" value={draft.tcpOptions} onChange={event => set('tcpOptions', Number(event.target.value))}>
                <option value={0}>None · 0 B</option><option value={12}>Timestamps · 12 B</option><option value={40}>40 bytes</option>
              </select>
            </div>
          </div>
          <label htmlFor="data-size">Application data <span>bytes</span></label>
          <input id="data-size" type="number" min={1} max={60000} value={draft.dataSize} onChange={event => set('dataSize', event.target.value)} />
          <label className="check-label"><input type="checkbox" checked={draft.vlan} onChange={event => set('vlan', event.target.checked)} /> Add an 802.1Q VLAN tag (+4 B)</label>
          {error && <p className="error" role="alert">{error}</p>}
          <button type="button" className="outline-button reset-button" onClick={() => { setDraft(toDraft(defaultSizeInput)); setDontFragment(false); }}>Reset example ↺</button>
        </div>
        {result ? <SizeResults input={input} result={result} /> : <div className="lab-output muted">Enter valid values to calculate.</div>}
        <FragmentExperiment input={input} result={result} dontFragment={dontFragment} onDontFragmentChange={setDontFragment} />
      </div>
    </>
  );
}

function SizeResults({ input, result }: { input: SizeInput; result: SizeResult }) {
  const components: [string, number, string][] = [
    ['ETH', result.ethernetHeader, 'var(--amber)'], ['IP', result.ipHeader, 'var(--green)'], ['TCP', result.tcpHeader, 'var(--blue)'],
    ['Data', result.firstData, 'var(--purple)'], ...(result.padding ? [['Pad', result.padding, '#b2bfd0'] as [string, number, string]] : []),
    ['FCS', fcsBytes, '#d6a65d']
  ];
  const fits = result.capacity > 0;
  return (
    <section className="lab-output" aria-live="polite" aria-labelledby="segmentation-title">
      <h2 id="segmentation-title" className="pane-title"><LayerTag layer="transport" name={false} /> TCP segmentation</h2>
      <div className="metrics">
        <div>
          <span>MSS advertisement example</span>
          <strong>{format(result.advertisedMss)} <small>B</small></strong>
          <p>Link MTU − fixed IPv4 &amp; TCP headers</p>
        </div>
        <div className="metric-highlight">
          <span>Actual TCP data capacity</span>
          <strong>{format(result.capacity)} <small>B</small></strong>
          <p>{fits ? 'Per segment, after all limits and options' : 'Headers/options leave no room for data'}</p>
        </div>
      </div>
      <div className="formula" title="Minimum of link/path MTU minus fixed headers and peer MSS; then subtract IPv4 options and TCP options.">
        min({format(result.effectiveMtu)} − 40, {format(input.peerMss)}) − {input.ipOptions} − {input.tcpOptions} = {format(result.capacity)} B{fits ? '' : ' (clamped at zero)'}
      </div>
      {fits && (
        <>
          <div className="packet-bar" aria-label="First packet byte breakdown">
            {components.map(([name, bytes, color]) => (
              <div key={name} style={{ flex: bytes, background: color }} title={`${name}: ${bytes} bytes`}>{bytes > 100 ? `${format(bytes)} B` : ''}</div>
            ))}
          </div>
          <div className="byte-key">
            {components.map(([name, bytes, color]) => <span key={name}><i style={{ background: color }}></i><LayerTag layer={byteKeyLayers[name]!} name={false} />{byteKeyTerms[name] ? <Term id={byteKeyTerms[name]}>{name}</Term> : name} {format(bytes)} B</span>)}
          </div>
        </>
      )}
      <div className="result-line">
        <strong>{fits ? `${format(result.segments)} TCP segment${result.segments === 1 ? '' : 's'} for ${format(input.dataSize)} B` : 'No data segment fits these constraints'}</strong>
        <span>{fits && <>First frame: {format(result.frameWithFcs)} B including <Term id="fcs" /></>}</span>
      </div>
      <p className="lab-explanation">
        <GlossaryText>{fits
          ? `First segment: ${format(result.firstData)} B of data. Last: ${format(result.lastData)} B. First IPv4 packet: ${format(result.ipLength)} B. The core would serialize ${format(result.frameWithoutFcs)} Ethernet bytes; hardware adds the 4-byte FCS. This is a maximum-size packing model; real send sizes also depend on buffering, flow control and congestion control.`
          : 'Reduce header options or raise the limiting MTU / peer MSS to carry data. No packet is drawn for an impossible combination.'}</GlossaryText>
      </p>
      <div className="callout">
        <strong>MTU ≠ frame size. MSS ≠ packet size.</strong>
        <p><GlossaryText>The IP MTU includes the IP header, but excludes Ethernet headers and FCS. Advertised MSS excludes fixed IP and TCP headers; options reduce the data actually sent. A VLAN tag grows the frame, not the IP packet.</GlossaryText> <Link className="inline-link" to="/layers/transport/gotchas">More transport gotchas</Link></p>
      </div>
    </section>
  );
}
