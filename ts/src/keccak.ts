// Pure-TypeScript Keccak-256 (the original Keccak padding 0x01, as used by
// Ethereum — NOT NIST SHA3-256, which uses 0x06). Vendored deliberately so the
// verifier carries no runtime dependency for the keccak domain; mirrors the Go
// client's keccak.go and the producer's pure-stdlib keccak256.py. Lanes are
// 64-bit, held as BigInt and masked to 64 bits after every widening op.

const MASK: bigint = (1n << 64n) - 1n;

const RC: bigint[] = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
  0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
  0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
  0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];

const ROT: number[] = [1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44];
const PILN: number[] = [10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1];

function rotl(x: bigint, n: number): bigint {
  const b = BigInt(n);
  return ((x << b) | (x >> (64n - b))) & MASK;
}

function keccakF1600(a: bigint[]): void {
  const bc: bigint[] = new Array<bigint>(5);
  for (let round = 0; round < 24; round++) {
    // Theta
    for (let i = 0; i < 5; i++) bc[i] = a[i] ^ a[i + 5] ^ a[i + 10] ^ a[i + 15] ^ a[i + 20];
    for (let i = 0; i < 5; i++) {
      const t = bc[(i + 4) % 5] ^ rotl(bc[(i + 1) % 5], 1);
      for (let j = 0; j < 25; j += 5) a[j + i] ^= t;
    }
    // Rho + Pi
    let t = a[1];
    for (let i = 0; i < 24; i++) {
      const j = PILN[i];
      const tmp = a[j];
      a[j] = rotl(t, ROT[i]);
      t = tmp;
    }
    // Chi
    for (let j = 0; j < 25; j += 5) {
      for (let i = 0; i < 5; i++) bc[i] = a[j + i];
      for (let i = 0; i < 5; i++) a[j + i] ^= (~bc[(i + 1) % 5] & MASK) & bc[(i + 2) % 5];
    }
    // Iota
    a[0] ^= RC[round];
  }
}

function load64LE(buf: Uint8Array, off: number): bigint {
  let r = 0n;
  for (let i = 7; i >= 0; i--) r = (r << 8n) | BigInt(buf[off + i]);
  return r;
}

function store64LE(buf: Uint8Array, off: number, v: bigint): void {
  for (let i = 0; i < 8; i++) {
    buf[off + i] = Number(v & 0xffn);
    v >>= 8n;
  }
}

/** keccak256 returns the 32-byte Ethereum keccak-256 digest of data. */
export function keccak256(data: Uint8Array): Uint8Array {
  const rate = 136; // 1088-bit rate for 256-bit capacity
  const a: bigint[] = new Array<bigint>(25).fill(0n);
  const len = data.length;
  let off = 0;
  while (len - off >= rate) {
    for (let i = 0; i < rate / 8; i++) a[i] ^= load64LE(data, off + i * 8);
    keccakF1600(a);
    off += rate;
  }
  const block = new Uint8Array(rate);
  block.set(data.subarray(off));
  block[len - off] ^= 0x01; // keccak domain padding (SHA3 would be 0x06)
  block[rate - 1] ^= 0x80;
  for (let i = 0; i < rate / 8; i++) a[i] ^= load64LE(block, i * 8);
  keccakF1600(a);
  const out = new Uint8Array(32);
  for (let i = 0; i < 4; i++) store64LE(out, i * 8, a[i]);
  return out;
}
