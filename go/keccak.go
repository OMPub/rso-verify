package rsoverify

// Pure-Go Keccak-256 (the original Keccak padding 0x01, as used by Ethereum —
// NOT NIST SHA3-256, which uses 0x06). Vendored deliberately: this verifier
// depends only on the Go standard library, so a third party can build it with
// `go build` and nothing else. Mirrors the producer's pure-stdlib
// attestation/keccak256.py.

import "encoding/binary"

var keccakRC = [24]uint64{
	0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
	0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
	0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
	0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
	0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
	0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
}

var keccakRot = [24]uint{1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44}
var keccakPiln = [24]int{10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1}

func rotl64(x uint64, n uint) uint64 { return (x << n) | (x >> (64 - n)) }

func keccakF1600(a *[25]uint64) {
	var bc [5]uint64
	for round := 0; round < 24; round++ {
		// Theta
		for i := 0; i < 5; i++ {
			bc[i] = a[i] ^ a[i+5] ^ a[i+10] ^ a[i+15] ^ a[i+20]
		}
		for i := 0; i < 5; i++ {
			t := bc[(i+4)%5] ^ rotl64(bc[(i+1)%5], 1)
			for j := 0; j < 25; j += 5 {
				a[j+i] ^= t
			}
		}
		// Rho + Pi
		t := a[1]
		for i := 0; i < 24; i++ {
			j := keccakPiln[i]
			tmp := a[j]
			a[j] = rotl64(t, keccakRot[i])
			t = tmp
		}
		// Chi
		for j := 0; j < 25; j += 5 {
			for i := 0; i < 5; i++ {
				bc[i] = a[j+i]
			}
			for i := 0; i < 5; i++ {
				a[j+i] ^= (^bc[(i+1)%5]) & bc[(i+2)%5]
			}
		}
		// Iota
		a[0] ^= keccakRC[round]
	}
}

// Keccak256 returns the 32-byte Ethereum keccak-256 digest of data.
func Keccak256(data []byte) [32]byte {
	const rate = 136 // 1088-bit rate for 256-bit capacity
	var a [25]uint64
	buf := data
	for len(buf) >= rate {
		for i := 0; i < rate/8; i++ {
			a[i] ^= binary.LittleEndian.Uint64(buf[i*8:])
		}
		keccakF1600(&a)
		buf = buf[rate:]
	}
	var block [rate]byte
	copy(block[:], buf)
	block[len(buf)] ^= 0x01 // keccak domain padding (SHA3 would be 0x06)
	block[rate-1] ^= 0x80
	for i := 0; i < rate/8; i++ {
		a[i] ^= binary.LittleEndian.Uint64(block[i*8:])
	}
	keccakF1600(&a)
	var out [32]byte
	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint64(out[i*8:], a[i])
	}
	return out
}
