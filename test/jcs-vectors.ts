/**
 * JCS (RFC 8785) canonicalization test vectors -- ACP spec Appendix D.
 *
 * Run with:  npx tsx test/jcs-vectors.ts
 */

import _canonicalize from 'canonicalize';
const canonicalize = _canonicalize as unknown as (obj: unknown) => string | undefined;

interface Vector {
  name: string;
  input: string;
  expected: string;
}

const vectors: Vector[] = [
  {
    name: 'Vector 1 -- Key ordering',
    input:
      '{"type":"request","acp":"1.0","to":"did:web:b.com:agent","id":"msg_001","from":"did:web:a.com:agent","createdAt":"2026-04-12T00:00:00Z","body":{"text":"hello"}}',
    expected:
      '{"acp":"1.0","body":{"text":"hello"},"createdAt":"2026-04-12T00:00:00Z","from":"did:web:a.com:agent","id":"msg_001","to":"did:web:b.com:agent","type":"request"}',
  },
  {
    name: 'Vector 2 -- Numerics and nesting',
    input: '{"count":1,"rate":0.5,"nested":{"z":true,"a":false},"list":[3,1,2]}',
    expected: '{"count":1,"list":[3,1,2],"nested":{"a":false,"z":true},"rate":0.5}',
  },
  {
    name: 'Vector 3 -- Unicode',
    input: '{"emoji":"☕","path":"/données/café","null_val":null,"empty":""}',
    expected: '{"emoji":"☕","empty":"","null_val":null,"path":"/données/café"}',
  },
];

let allPassed = true;

for (const v of vectors) {
  const parsed = JSON.parse(v.input);
  const result = canonicalize(parsed);

  if (result === v.expected) {
    console.log(`PASS  ${v.name}`);
  } else {
    console.log(`FAIL  ${v.name}`);
    console.log(`  expected: ${v.expected}`);
    console.log(`  got:      ${result}`);
    allPassed = false;
  }
}

process.exit(allPassed ? 0 : 1);
