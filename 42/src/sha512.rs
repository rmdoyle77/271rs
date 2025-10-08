// Pure-Rust SHA-512 (FIPS 180-4) implementation.
// No external dependencies; streaming-friendly.

pub struct Sha512 {
    h: [u64; 8],
    len_bits: u128,     // total message length in bits
    buf: Vec<u8>,       // partial block buffer
}

impl Sha512 {
    pub fn new() -> Self {
        Self {
            h: [
                0x6a09e667f3bcc908,
                0xbb67ae8584caa73b,
                0x3c6ef372fe94f82b,
                0xa54ff53a5f1d36f1,
                0x510e527fade682d1,
                0x9b05688c2b3e6c1f,
                0x1f83d9abfb41bd6b,
                0x5be0cd19137e2179,
            ],
            len_bits: 0,
            buf: Vec::with_capacity(128),
        }
    }

    #[inline(always)]
    fn rotr(x: u64, n: u32) -> u64 { x.rotate_right(n) }

    #[inline(always)]
    fn big_sigma0(x: u64) -> u64 { Self::rotr(x, 28) ^ Self::rotr(x, 34) ^ Self::rotr(x, 39) }

    #[inline(always)]
    fn big_sigma1(x: u64) -> u64 { Self::rotr(x, 14) ^ Self::rotr(x, 18) ^ Self::rotr(x, 41) }

    #[inline(always)]
    fn small_sigma0(x: u64) -> u64 { Self::rotr(x, 1) ^ Self::rotr(x, 8) ^ (x >> 7) }

    #[inline(always)]
    fn small_sigma1(x: u64) -> u64 { Self::rotr(x, 19) ^ Self::rotr(x, 61) ^ (x >> 6) }

    #[inline(always)]
    fn ch(x: u64, y: u64, z: u64) -> u64 { (x & y) ^ ((!x) & z) }

    #[inline(always)]
    fn maj(x: u64, y: u64, z: u64) -> u64 { (x & y) ^ (x & z) ^ (y & z) }

    pub fn update(&mut self, data: &[u8]) {
        self.len_bits = self.len_bits.wrapping_add((data.len() as u128) * 8);

        let mut input = data;
        if !self.buf.is_empty() {
            let to_take = core::cmp::min(128 - self.buf.len(), input.len());
            self.buf.extend_from_slice(&input[..to_take]);
            input = &input[to_take..];
            if self.buf.len() == 128 {
                Self::process_block(&mut self.h, &self.buf);
                self.buf.clear();
            }
        }

        while input.len() >= 128 {
            let (block, rest) = input.split_at(128);
            Self::process_block(&mut self.h, block);
            input = rest;
        }

        if !input.is_empty() {
            self.buf.extend_from_slice(input);
        }
    }

    pub fn finalize(mut self) -> [u8; 64] {
        // Padding: append 0x80, then zeros so that length ≡ 112 mod 128,
        // then append 128-bit big-endian length (len_bits).
        self.buf.push(0x80);

        if self.buf.len() > 112 {
            // not enough space for length; pad this block and process
            self.buf.resize(128, 0);
            Self::process_block(&mut self.h, &self.buf);
            self.buf.clear();
        }
        self.buf.resize(112, 0);

        // append 128-bit big-endian length
        let len = self.len_bits;
        let mut len_block = [0u8; 16];
        for i in 0..16 {
            len_block[15 - i] = ((len >> (i * 8)) & 0xFF) as u8;
        }
        self.buf.extend_from_slice(&len_block);
        debug_assert_eq!(self.buf.len(), 128);

        Self::process_block(&mut self.h, &self.buf);

        // Produce digest (big-endian u64s).
        let mut out = [0u8; 64];
        for (i, &word) in self.h.iter().enumerate() {
            let be = word.to_be_bytes();
            out[i * 8..(i + 1) * 8].copy_from_slice(&be);
        }
        out
    }

    pub fn hexdigest(self) -> String {
        let digest = self.finalize();
        let mut s = String::with_capacity(128);
        for b in digest {
            use core::fmt::Write;
            write!(&mut s, "{:02x}", b).unwrap();
        }
        s
    }

    fn process_block(state: &mut [u64; 8], block: &[u8]) {
        debug_assert_eq!(block.len(), 128);

        const K: [u64; 80] = [
            0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
            0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
            0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
            0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
            0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
            0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
            0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
            0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
            0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
            0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
            0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
            0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
            0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
            0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
            0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
            0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
            0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
            0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
            0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
            0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
        ];

        let mut w = [0u64; 80];

        // W[0..16)
        for (i, chunk) in block.chunks_exact(8).take(16).enumerate() {
            w[i] = u64::from_be_bytes([
                chunk[0], chunk[1], chunk[2], chunk[3],
                chunk[4], chunk[5], chunk[6], chunk[7],
            ]);
        }
        // W[16..80)
        for t in 16..80 {
            w[t] = Self::small_sigma1(w[t - 2])
                .wrapping_add(w[t - 7])
                .wrapping_add(Self::small_sigma0(w[t - 15]))
                .wrapping_add(w[t - 16]);
        }

        // Working vars
        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];
        let mut f = state[5];
        let mut g = state[6];
        let mut h = state[7];

        for t in 0..80 {
            let t1 = h
                .wrapping_add(Self::big_sigma1(e))
                .wrapping_add(Self::ch(e, f, g))
                .wrapping_add(K[t])
                .wrapping_add(w[t]);
            let t2 = Self::big_sigma0(a).wrapping_add(Self::maj(a, b, c));

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }
}

