/** Classic 16-bytes-per-line hex dump with offsets and printable ASCII. */
export function hexDump(hex: string): string {
  const bytes = hex.match(/.{2}/g) ?? [];
  const lines: string[] = [];
  for (let offset = 0; offset < bytes.length; offset += 16) {
    const line = bytes.slice(offset, offset + 16);
    const ascii = line.map(byte => { const code = parseInt(byte, 16); return code >= 32 && code <= 126 ? String.fromCharCode(code) : '.'; }).join('');
    lines.push(`${offset.toString(16).padStart(4, '0')}  ${line.join(' ').padEnd(47, ' ')}  ${ascii}`);
  }
  return lines.join('\n');
}
