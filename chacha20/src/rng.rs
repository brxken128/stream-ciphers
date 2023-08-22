use crate::{ChaCha12, ChaCha20, ChaCha8, XChaCha12, XChaCha20, XChaCha8, STATE_WORDS};
use cipher::{KeyIvInit, StreamCipher};
use core::mem;
use rand_core::{
    block::{BlockRng, BlockRngCore},
    CryptoRng, RngCore, SeedableRng,
};

#[cfg(feature = "zeroize")]
use cipher::zeroize::ZeroizeOnDrop;

const KEY_LEN: usize = 32;

macro_rules! generate_rng {
    ($cipher:ident, $name:ident, $core:ident, $iv_len:expr) => {
        #[doc = "A CSPRNG using the [`"]
        #[doc = stringify!($cipher)]
        #[doc = "`] stream cipher."]
        pub struct $name(BlockRng<$core>);

        impl CryptoRng for $name {}

        impl RngCore for $name {
            #[inline]
            #[must_use]
            fn next_u32(&mut self) -> u32 {
                self.0.next_u32()
            }

            #[inline]
            #[must_use]
            fn next_u64(&mut self) -> u64 {
                self.0.next_u64()
            }

            #[inline]
            fn fill_bytes(&mut self, dest: &mut [u8]) {
                self.0.fill_bytes(dest)
            }

            #[inline]
            fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
                self.0.try_fill_bytes(dest)
            }
        }

        impl SeedableRng for $name {
            type Seed = [u8; KEY_LEN];

            #[inline]
            #[must_use]
            fn from_seed(seed: Self::Seed) -> Self {
                let core = $core::from_seed(seed);
                Self(BlockRng::new(core))
            }
        }

        impl $name {
            /// Attempts to create the RNG using the system's entropy sources (via the `getrandom` crate)
            ///
            /// Usually this will be the go-to choice as most systems have good entropy sources, and
            /// therefore the entropy of the output will be high.
            #[inline]
            #[must_use]
            pub fn from_entropy() -> Self {
                let mut seed = [0u8; KEY_LEN];
                getrandom::getrandom(&mut seed)
                    .expect("We were unable to get a good entropy source via `getrandom`.");
                Self::from_seed(seed)
            }
        }

        #[doc = "RNG core behind [`"]
        #[doc = stringify!($name)]
        #[doc = "`]."]
        pub struct $core {
            cipher: $cipher,
            counter: u64,
        }

        impl SeedableRng for $core {
            type Seed = [u8; KEY_LEN];

            #[inline]
            #[must_use]
            fn from_seed(seed: Self::Seed) -> Self {
                Self {
                    cipher: $cipher::new(&seed.into(), &[0u8; $iv_len].into()),
                    counter: 0,
                }
            }
        }

        impl BlockRngCore for $core {
            type Item = u32;
            type Results = [u32; STATE_WORDS];

            #[inline]
            fn generate(&mut self, results: &mut Self::Results) {
                let mut o = [self.counter as u8; mem::size_of::<Self::Item>()];
                for i in 0..STATE_WORDS {
                    self.cipher.apply_keystream(&mut o);
                    results[i] = Self::Item::from_le_bytes(o);
                    self.counter += 1;
                }
            }
        }

        #[cfg(feature = "zeroize")]
        #[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
        impl ZeroizeOnDrop for $name {}

        #[cfg(feature = "zeroize")]
        #[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
        impl ZeroizeOnDrop for $core {}
    };
}

generate_rng!(ChaCha8, ChaCha8Rng, ChaCha8RngCore, 12);
generate_rng!(ChaCha12, ChaCha12Rng, ChaCha12RngCore, 12);
generate_rng!(ChaCha20, ChaCha20Rng, ChaCha20RngCore, 12);
generate_rng!(XChaCha8, XChaCha8Rng, XChaCha8RngCore, 24);
generate_rng!(XChaCha12, XChaCha12Rng, XChaCha12RngCore, 24);
generate_rng!(XChaCha20, XChaCha20Rng, XChaCha20RngCore, 24);

#[cfg(test)]
mod tests {
    use super::ChaCha20Rng;
    use rand_core::{RngCore, SeedableRng};

    #[test]
    fn chacha20rng_fill_512_with_entropy() {
        let mut rng = ChaCha20Rng::from_entropy();

        let mut buf = [0u8; 512];
        rng.fill_bytes(&mut buf);

        assert_ne!([0u8; 512], buf);
    }

    #[test]
    fn chacha20rng_fill_1024_with_entropy() {
        let mut rng = ChaCha20Rng::from_entropy();

        let mut buf = [0u8; 1024];
        rng.fill_bytes(&mut buf);

        assert_ne!([0u8; 1024], buf);
    }

    #[test]
    fn chacha20rng_u32_same_seed() {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);

        for _ in 0..8 {
            let mut buf1 = [0u32; 32];
            let mut buf2 = [0u32; 32];
            for _ in 0..2 {
                for i in 0..32 {
                    buf1[i] = rng.next_u32();
                }
                for i in 0..32 {
                    buf2[i] = rng.next_u32();
                }
            }

            assert!(buf1.iter().zip(buf2.iter()).any(|(x, y)| x != y));
        }
    }

    #[test]
    fn chacha20rng_u32_diff_seed() {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        let mut rng2 = ChaCha20Rng::from_seed([1u8; 32]);

        for _ in 0..8 {
            let mut buf1 = [0u32; 32];
            let mut buf2 = [0u32; 32];
            for _ in 0..2 {
                for i in 0..32 {
                    buf1[i] = rng.next_u32();
                }
                for i in 0..32 {
                    buf2[i] = rng2.next_u32();
                }
            }

            assert!(buf1.iter().zip(buf2.iter()).any(|(x, y)| x != y));
        }
    }

    #[test]
    fn chacha20rng_u64_same_seed() {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);

        for _ in 0..8 {
            let mut buf1 = [0u64; 32];
            let mut buf2 = [0u64; 32];
            for _ in 0..2 {
                for i in 0..32 {
                    buf1[i] = rng.next_u64();
                }
                for i in 0..32 {
                    buf2[i] = rng.next_u64();
                }
            }

            assert!(buf1.iter().zip(buf2.iter()).any(|(x, y)| x != y));
        }
    }

    #[test]
    fn chacha20rng_u64_diff_seed() {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        let mut rng2 = ChaCha20Rng::from_seed([1u8; 32]);

        for _ in 0..8 {
            let mut buf1 = [0u64; 32];
            let mut buf2 = [0u64; 32];
            for _ in 0..2 {
                for i in 0..32 {
                    buf1[i] = rng.next_u64();
                }
                for i in 0..32 {
                    buf2[i] = rng2.next_u64();
                }
            }

            assert!(buf1.iter().zip(buf2.iter()).any(|(x, y)| x != y));
        }
    }

    // This RNG does not produce the same output as `rand_chacha`
    #[test]
    #[should_panic]
    fn chacha20rng_vs_rand_chacha_u64() {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        let mut rng2 = rand_chacha::ChaCha20Rng::from_seed([0u8; 32]);

        for _ in 0..8 {
            let mut buf1 = [0u64; 32];
            let mut buf2 = [0u64; 32];
            for _ in 0..2 {
                for i in 0..32 {
                    buf1[i] = rng.next_u64();
                }
                for i in 0..32 {
                    buf2[i] = rng2.next_u64();
                }
            }

            assert!(buf1.iter().zip(buf2.iter()).all(|(x, y)| x == y));
        }
    }

    // This RNG does not produce the same output as `rand_chacha`
    #[test]
    #[should_panic]
    fn chacha20rng_vs_rand_chacha_128_bytes() {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        let mut rng2 = rand_chacha::ChaCha20Rng::from_seed([0u8; 32]);

        let mut buf1 = [0u8; 128];
        let mut buf2 = [0u8; 128];

        rng.fill_bytes(&mut buf1);
        rng2.fill_bytes(&mut buf2);

        assert_eq!(buf1, buf2);
    }
}
