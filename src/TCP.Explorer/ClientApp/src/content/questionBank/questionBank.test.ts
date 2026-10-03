import { questionBank, examSections, assembleQuestion } from './index';
import { fundamentals } from './fundamentals';
import { blueprintObjectives, blueprintStatus, topicReferences } from './references';

const question = (id: string) => questionBank.find(q => q.id === id)!;
const answer = (id: string) => { const q = question(id); return q.choices[q.answer]!; };

test('the bank has 200 unique prompts and explicit IDs at the published domain weights', () => {
  expect(questionBank).toHaveLength(200);
  expect(new Set(questionBank.map(q => q.id)).size).toBe(200);
  expect(new Set(questionBank.map(q => q.prompt)).size).toBe(200);
  const expected = [['fundamentals', 40, 20], ['access', 40, 20], ['connectivity', 50, 25], ['services', 20, 10], ['security', 30, 15], ['automation', 20, 10]] as const;
  for (const [id, count, weight] of expected) {
    expect(questionBank.filter(q => q.section === id)).toHaveLength(count);
    expect(examSections.find(section => section.id === id)?.weight).toBe(weight);
  }
});

test('parent tags match the separately transcribed checklist and references are available', () => {
  expect(new Set(questionBank.map(q => q.objective))).toEqual(new Set(blueprintObjectives));
  for (const q of questionBank) {
    expect(q.choices).toHaveLength(4);
    expect(new Set(q.choices).size).toBe(4);
    expect(q.choiceIds).toEqual(q.choices);
    expect(q.answer).toBeGreaterThanOrEqual(0);
    expect(q.answer).toBeLessThan(4);
    expect(q.revision).toMatch(/^[0-9a-f]{16}$/);
    expect(q.explanation.trim()).not.toBe('');
    expect(topicReferences(q.objective).length).toBeGreaterThan(0);
    for (const reference of topicReferences(q.objective)) expect(new URL(reference.url).protocol).toBe('https:');
  }
});

test('answer positions do not repeat the ordinal four-step key or favor one letter', () => {
  const counts = [0, 0, 0, 0];
  let oldPatternMatches = 0;
  for (const q of questionBank) {
    counts[q.answer]!++;
    const ordinal = questionBank.filter(item => item.section === q.section).indexOf(q) + 1;
    if (q.answer === (4 - (ordinal - 1) % 4) % 4) oldPatternMatches++;
  }
  expect(oldPatternMatches).toBeLessThan(80);
  for (const count of counts) { expect(count).toBeGreaterThanOrEqual(25); expect(count).toBeLessThanOrEqual(75); }
  for (const section of examSections) {
    const bank = questionBank.filter(q => q.section === section.id);
    for (let residue = 0; residue < 4; residue++) {
      expect(new Set(bank.filter((_, i) => i % 4 === residue).map(q => q.answer)).size).toBeGreaterThan(1);
    }
  }
});

test('correct choices do not dominate the uniquely-longest-option cue', () => {
  const uniquelyLongest = questionBank.filter(q => {
    const lengths = q.choices.map(c => c.length), max = Math.max(...lengths);
    return lengths[q.answer] === max && lengths.filter(n => n === max).length === 1;
  });
  // Editorial regression guard, not a calibrated measure of exam difficulty.
  expect(uniquelyLongest.length).toBeLessThanOrEqual(60);
});

test('identity and ordering survive source reordering but substantive edits change revisions', () => {
  const original = fundamentals[0]!;
  const reordered = { ...original, distractors: [...original.distractors].reverse() as [string, string, string] };
  expect(assembleQuestion(reordered, 'fundamentals')).toEqual(assembleQuestion(original, 'fundamentals'));
  expect(fundamentals.slice().reverse().map(q => assembleQuestion(q, 'fundamentals')).find(q => q.id === original.id)).toEqual(question(original.id));
  const changed = assembleQuestion({ ...original, prompt: original.prompt + ' Assume a new topology.' }, 'fundamentals');
  expect(changed.id).toBe(original.id);
  expect(changed.revision).not.toBe(question(original.id).revision);
});

// These calculations verify authored numeric content independently of answer strings.
function ipv4(value: string): number {
  return value.split('.').reduce((acc, octet) => acc * 256 + Number(octet), 0);
}
function dotted(value: number): string {
  return [24, 16, 8, 0].map(bits => Math.floor(value / 2 ** bits) % 256).join('.');
}
function subnet(cidr: string) {
  const [address, prefix] = cidr.split('/');
  const size = 2 ** (32 - Number(prefix));
  const network = Math.floor(ipv4(address!) / size) * size;
  return { network, broadcast: network + size - 1, size, prefix: Number(prefix), address: ipv4(address!) };
}

test('IPv4 subnet keys follow independent boundary and capacity calculations', () => {
  const host = question('fundamentals-020').evidence.match(/\d+\.\d+\.\d+\.\d+\/\d+/)![0];
  const block = subnet(host);
  expect(answer('fundamentals-020')).toBe(`${dotted(block.network)} and ${dotted(block.broadcast)}`);
  const required = Number(question('fundamentals-021').prompt.match(/\d+/)![0]);
  const hostBits = Math.ceil(Math.log2(required + 2));
  expect(answer('fundamentals-021')).toBe(`/${32 - hostBits}`);
  const rangeHost = question('fundamentals-024').prompt.match(/\d+\.\d+\.\d+\.\d+\/\d+/)![0];
  const range = subnet(rangeHost);
  expect(answer('fundamentals-024')).toBe(`${dotted(range.network + 1)} through ${dotted(range.broadcast - 1)}`);
  const [left, right] = [...question('fundamentals-023').evidence.matchAll(/\d+\.\d+\.\d+\.\d+\/\d+/g)].map(match => subnet(match[0]));
  expect(left!.network).not.toBe(right!.network);
  expect(answer('fundamentals-023')).toBe(`No; their /26 networks are ${dotted(left!.network)} and ${dotted(right!.network)}`);
  expect(answer('connectivity-003')).toBe(dotted(2 ** 32 - 2 ** (32 - 23)));
});

test('exactly one VLSM allocation has valid boundaries, capacity, and no overlap', () => {
  const q = question('fundamentals-022');
  const requirements = [50, 25, 10];
  const valid = q.choices.filter(choice => {
    const blocks = choice.split(', ').map(subnet);
    return blocks.every((block, i) => block.address === block.network && block.size - 2 >= requirements[i]!)
      && blocks.every((a, i) => blocks.slice(i + 1).every(b => a.broadcast < b.network || b.broadcast < a.network));
  });
  expect(valid).toEqual([q.choices[q.answer]]);
});

test('IPv6 expansion and modified EUI-64 keys are computed independently', () => {
  const q = question('fundamentals-026');
  const compressed = q.prompt.match(/[0-9a-f]+:[0-9a-f:]+/)![0];
  const [left, right] = compressed.split('::');
  const before = left!.split(':'), after = right!.split(':');
  const groups = [...before, ...Array<string>(8 - before.length - after.length).fill('0'), ...after];
  expect(q.choices[q.answer]).toBe(groups.map(g => g.padStart(4, '0')).join(':'));
  const mac = question('fundamentals-031').evidence.split(': ').at(-1)!.split(':').map(b => parseInt(b, 16));
  mac[0] = mac[0]! ^ 2;
  const bytes = [...mac.slice(0, 3), 255, 254, ...mac.slice(3)];
  const hex = bytes.map(b => b.toString(16).padStart(2, '0')).join('');
  expect(answer('fundamentals-031')).toBe(hex.match(/.{4}/g)!.join(':'));
});

test('the longest IPv4 matching prefix wins and exactly one disabled JSON object is valid', () => {
  const q = question('connectivity-016');
  const destination = ipv4(q.prompt.match(/\d+\.\d+\.\d+\.\d+/)![0]);
  const candidates = q.choices.map(subnet).filter(route => destination >= route.network && destination <= route.broadcast);
  const best = candidates.sort((a, b) => b.prefix - a.prefix)[0]!;
  expect(q.choices[q.answer]).toBe(`${dotted(best.network)}/${best.prefix}`);
  const json = question('automation-020');
  const valid = json.choices.filter(choice => { try { return JSON.parse(choice).enabled === false; } catch { return false; } });
  expect(valid).toEqual([json.choices[json.answer]]);
});

test('added skill samples supply inspectable configuration or output and the right parent tag', () => {
  const samples = [['fundamentals-ipv6-interface', '1.8'], ['access-lldp-enable', '2.3'], ['access-central-switching', '2.9'], ['services-nat-pool', '4.1'], ['services-004', '4.2'], ['services-ntp-status', '4.2'], ['security-006', '5.3'], ['security-019', '5.7'], ['security-dai-config', '5.7'], ['security-023', '5.7'], ['security-wlan-auth', '5.10'], ['security-wlan-vlan', '5.10']];
  for (const [id, objective] of samples) { const q = question(id!); expect(q.objective).toBe(objective); expect(q.evidence.trim()).not.toBe(''); }
});

test('v1.1 retirement is clearly reported once v2.0 begins', () => {
  expect(blueprintStatus(new Date('2027-02-02T12:00:00Z'))).toContain('last testing day');
  expect(blueprintStatus(new Date('2027-02-03T12:00:00Z'))).toContain('retired');
});


test('the private-range key contains exactly the RFC 1918 blocks and boundaries', () => {
  const ranges = answer('fundamentals-private-ranges').split(', ').map(subnet);
  expect(ranges.map(block => [dotted(block.network), dotted(block.broadcast)])).toEqual([
    ['10.0.0.0', '10.255.255.255'],
    ['172.16.0.0', '172.31.255.255'],
    ['192.168.0.0', '192.168.255.255']
  ]);
  const q = question('fundamentals-private-ranges');
  expect(q.choices.filter(choice => choice.split(', ').map(subnet).every((block, i) =>
    block.network === ranges[i]!.network && block.broadcast === ranges[i]!.broadcast
  ))).toEqual([q.choices[q.answer]]);
});

test('the Windows gateway diagnosis follows the authored address and mask', () => {
  const q = question('fundamentals-windows-gateway');
  const address = q.evidence.match(/IPv4 Address: ([\d.]+)/)![1]!;
  const mask = q.evidence.match(/Subnet Mask: ([\d.]+)/)![1]!;
  const gateway = q.evidence.match(/Default Gateway: ([\d.]+)/)![1]!;
  const maskBits = ipv4(mask).toString(2);
  expect(maskBits).toMatch(/^1+0+$/);
  const prefix = maskBits.indexOf('0');
  const hostBlock = subnet(`${address}/${prefix}`);
  const gatewayBlock = subnet(`${gateway}/${prefix}`);
  expect(hostBlock.network).not.toBe(gatewayBlock.network);
  expect(hostBlock.address).toBeGreaterThan(hostBlock.network);
  expect(hostBlock.address).toBeLessThan(hostBlock.broadcast);
  expect(q.choices[q.answer]).toBe(`The /${prefix} mask places the gateway outside the host subnet`);
});
