const KECCAKF_ROUNDS: usize = 24;
pub const MDSIZE: usize = 64;

const KECCAKF_RNDC: [u64; 24] = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
    0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
];
const KECCAKF_ROTC: [usize; 24] = [1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44];
const KECCAKF_PILN: [usize; 24] = [10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1];

#[inline]
fn rotl64(x: u64, y: u64) -> u64 {
    ((x) << (y)) | ((x) >> (64 - (y)))
}

pub struct SHA3State {
    pub b: [u8; 200],
    pub q: [u64; 25],
}

pub struct SHA3 {
    st: SHA3State,
    pt: usize,
    rsiz: usize,
    mdlen: usize,
}

impl SHA3 {
    pub fn new(mdlen: usize) -> Self {
        Self {
            st: SHA3State {
                b: [0; 200],
                q: [0; 25],
            },
            pt: 0,
            rsiz: 200 - 2 * mdlen,
            mdlen,
        }
    }

    #[cfg(feature = "big_endian")]
    fn reverse(q: &mut [u64; 25]) {
        for i in 0..25 {
            q[i] = q[i] >> 56
                | (q[i] >> 40 & 0xFF << 8)
                | (q[i] >> 24 & 0xFF << 16)
                | (q[i] >> 8 & 0xFF << 24)
                | (q[i] << 8 & 0xFF << 32)
                | (q[i] << 24 & 0xFF << 40)
                | (q[i] << 40 & 0xFF << 48)
                | (q[i] << 56 & 0xFF << 56);
        }
    }

    fn sha3_keccakf(&mut self) {
        let mut q = self.st.q;

        let mut t: u64;
        let mut bc: [u64; 5] = [0; 5];

        #[cfg(feature = "big_endian")]
        self.reverse(q);

        for r in 0..KECCAKF_ROUNDS {
            for i in 0..5 {
                bc[i] = q[i] ^ q[i + 5] ^ q[i + 10] ^ q[i + 15] ^ q[i + 20];
            }

            for i in 0..5 {
                t = bc[(i + 4) % 5] ^ rotl64(bc[(i + 1) % 5], 1);
                for j in (0..25).step_by(5) {
                    q[j + i] ^= t;
                }
            }

            t = q[1];
            for i in 0..24 {
                let j = KECCAKF_PILN[i];
                bc[0] = q[j];
                q[j] = rotl64(t, KECCAKF_ROTC[i] as u64);
                t = bc[0];
            }

            for j in (0..25).step_by(5) {
                for i in 0..5 {
                    bc[i] = q[j + i];
                }
                for i in 0..5 {
                    q[j + i] ^= (!bc[(i + 1) % 5]) & bc[(i + 2) % 5];
                }
            }

            q[0] ^= KECCAKF_RNDC[r];
        }

        #[cfg(feature = "big_endian")]
        self.reverse(q);
    }

    pub fn sha3_update(&mut self, data: *const u8, len: usize) -> isize {
        let mut j = self.pt;
        for i in 0..len {
            self.st.b[j] ^= unsafe { *data.offset(i as isize) };
            j += 1;
            if j >= self.rsiz {
                self.sha3_keccakf();
                j = 0;
            }
        }
        self.pt = j;
        1
    }

    pub fn sha3_final(&mut self, md: *mut u8) -> isize {
        self.st.b[self.pt] ^= 0x06;
        self.st.b[self.rsiz - 1] ^= 0x80;
        self.sha3_keccakf();

        for i in 0..self.mdlen {
            unsafe { *md.offset(i as isize) = self.st.b[i]; }
        }
        1
    }
}

pub fn sha3(data_in: *const u8, inlen: usize, md: *mut u8, mdlen: usize) {
    let mut sha = SHA3::new(mdlen);
    sha.sha3_update(data_in, inlen);
    sha.sha3_final(md);
}
