//! Shared fixed-width arithmetic for the class-group VDF (vdf_cg.rs): little-endian u64 limbs,
//! Montgomery multiplication (CIOS), Miller-Rabin and Fiat-Shamir HashToPrime.
//!
//! Split out of the former RSA-2048 Wesolowski module, which is removed: the only VDF group is the
//! class group of an imaginary quadratic order (no trusted setup). No allocator, stack-only
//! buffers; every value handled here is public.
use sha2::{Digest, Sha256};
use crate::{Error, Result};

/// Limbs of a 256-bit prime (HashToPrime output, prime-form leading coefficients).
pub(crate) const PL: usize = 4;

pub(crate) type Limbs<const K: usize> = [u64; K];

#[inline(always)]
fn mac(a: u64, b: u64, c: u64, carry: u64) -> (u64, u64) {
    let t = (a as u128) + (b as u128) * (c as u128) + (carry as u128);
    (t as u64, (t >> 64) as u64)
}

#[inline(always)]
fn adc(a: u64, b: u64, carry: u64) -> (u64, u64) {
    let t = (a as u128) + (b as u128) + (carry as u128);
    (t as u64, (t >> 64) as u64)
}

#[inline(always)]
fn sbb(a: u64, b: u64, borrow: u64) -> (u64, u64) {
    let t = (a as u128).wrapping_sub((b as u128) + (borrow as u128));
    (t as u64, ((t >> 64) as u64) & 1)
}

/// a - b and the final borrow (1 when a < b).
pub(crate) fn sub<const K: usize>(a: &Limbs<K>, b: &Limbs<K>) -> (Limbs<K>, u64) {
    let mut out = [0u64; K];
    let mut borrow = 0;
    for i in 0..K {
        let (d, br) = sbb(a[i], b[i], borrow);
        out[i] = d;
        borrow = br;
    }
    (out, borrow)
}

/// 2a and the bit shifted out.
pub(crate) fn shl1<const K: usize>(a: &Limbs<K>) -> (Limbs<K>, u64) {
    let mut out = [0u64; K];
    let mut carry = 0;
    for i in 0..K {
        out[i] = (a[i] << 1) | carry;
        carry = a[i] >> 63;
    }
    (out, carry)
}

/// `yes` when choice == 1, else `no` (branch-free).
pub(crate) fn select<const K: usize>(yes: &Limbs<K>, no: &Limbs<K>, choice: u64) -> Limbs<K> {
    let mask = 0u64.wrapping_sub(choice & 1);
    let mut out = [0u64; K];
    for i in 0..K {
        out[i] = (yes[i] & mask) | (no[i] & !mask);
    }
    out
}

pub(crate) fn is_zero<const K: usize>(a: &Limbs<K>) -> bool {
    a.iter().fold(0u64, |acc, x| acc | x) == 0
}

pub(crate) fn eq<const K: usize>(a: &Limbs<K>, b: &Limbs<K>) -> bool {
    a.iter().zip(b.iter()).fold(0u64, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub(crate) fn from_be<const K: usize>(b: &[u8]) -> Limbs<K> {
    let mut out = [0u64; K];
    for i in 0..K {
        let end = b.len() - 8 * i;
        let mut w = [0u8; 8];
        w.copy_from_slice(&b[end - 8..end]);
        out[i] = u64::from_be_bytes(w);
    }
    out
}

pub(crate) fn to_be<const K: usize>(a: &Limbs<K>, out: &mut [u8]) {
    let n = out.len();
    for i in 0..K {
        out[n - 8 * (i + 1)..n - 8 * i].copy_from_slice(&a[i].to_be_bytes());
    }
}

/// Montgomery arithmetic modulo an odd n (R = 2^(64K)).
pub(crate) struct Monty<const K: usize> {
    pub(crate) n: Limbs<K>,
    n0: u64,
    /// R mod n: the Montgomery form of 1.
    pub(crate) one: Limbs<K>,
    r2: Limbs<K>,
}

impl<const K: usize> Monty<K> {
    pub(crate) fn new(n: &Limbs<K>) -> Self {
        let mut inv: u64 = 1;
        for _ in 0..6 {
            inv = inv.wrapping_mul(2u64.wrapping_sub(n[0].wrapping_mul(inv)));
        }
        let mut m = Monty { n: *n, n0: inv.wrapping_neg(), one: [0; K], r2: [0; K] };
        let mut acc = [0u64; K];
        acc[0] = 1;
        for _ in 0..64 * K {
            acc = m.double(&acc);
        }
        m.one = acc;
        for _ in 0..64 * K {
            acc = m.double(&acc);
        }
        m.r2 = acc;
        m
    }

    /// 2a mod n for a < n.
    fn double(&self, a: &Limbs<K>) -> Limbs<K> {
        let (s, carry) = shl1(a);
        let (d, borrow) = sub(&s, &self.n);
        select(&d, &s, carry | (borrow ^ 1))
    }

    /// a * b * R^-1 mod n for a, b < n (CIOS).
    pub(crate) fn mul(&self, a: &Limbs<K>, b: &Limbs<K>) -> Limbs<K> {
        let mut t = [0u64; K];
        let mut t_hi: u64 = 0;
        for i in 0..K {
            let mut c = 0u64;
            for j in 0..K {
                let (lo, hi) = mac(t[j], a[j], b[i], c);
                t[j] = lo;
                c = hi;
            }
            let (s, c1) = adc(t_hi, c, 0);
            let m = t[0].wrapping_mul(self.n0);
            let (_, mut c2) = mac(t[0], m, self.n[0], 0);
            for j in 1..K {
                let (lo, hi) = mac(t[j], m, self.n[j], c2);
                t[j - 1] = lo;
                c2 = hi;
            }
            let (s2, c3) = adc(s, c2, 0);
            t[K - 1] = s2;
            t_hi = c1 + c3;
        }
        let (d, borrow) = sub(&t, &self.n);
        select(&d, &t, (t_hi & 1) | (borrow ^ 1))
    }

    pub(crate) fn to_mont(&self, a: &Limbs<K>) -> Limbs<K> {
        self.mul(a, &self.r2)
    }

    pub(crate) fn from_mont(&self, a: &Limbs<K>) -> Limbs<K> {
        let mut one = [0u64; K];
        one[0] = 1;
        self.mul(a, &one)
    }

    /// base^e (Montgomery form in and out), e as little-endian limbs, every bit processed.
    pub(crate) fn pow<const E: usize>(&self, base: &Limbs<K>, e: &Limbs<E>) -> Limbs<K> {
        let mut acc = self.one;
        for i in (0..64 * E).rev() {
            acc = self.mul(&acc, &acc);
            let t = self.mul(&acc, base);
            acc = select(&t, &acc, (e[i / 64] >> (i % 64)) & 1);
        }
        acc
    }
}

pub(crate) const SMALL_PRIMES: [u64; 24] = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97];

pub(crate) fn rem_small(a: &Limbs<PL>, p: u64) -> u64 {
    let mut r: u128 = 0;
    for i in (0..PL).rev() {
        r = ((r << 64) | a[i] as u128) % p as u128;
    }
    r as u64
}

/// Miller-Rabin with the bases 2 and SMALL_PRIMES (25 rounds) after trial division.
pub(crate) fn probable_prime(c: &Limbs<PL>) -> bool {
    if c[0] & 1 == 0 {
        return false;
    }
    if SMALL_PRIMES.iter().any(|&p| rem_small(c, p) == 0) {
        return false;
    }
    let m = Monty::<PL>::new(c);
    let mut one = [0u64; PL];
    one[0] = 1;
    let (d0, _) = sub(c, &one);
    let mut s = 0;
    let mut d = d0;
    while d[0] & 1 == 0 {
        for i in 0..PL {
            d[i] = (d[i] >> 1) | if i + 1 < PL { d[i + 1] << 63 } else { 0 };
        }
        s += 1;
    }
    let (minus_one, _) = sub(&m.n, &m.one);
    for &b in [2u64].iter().chain(SMALL_PRIMES.iter()) {
        let mut base = [0u64; PL];
        base[0] = b;
        let mut x = m.pow(&m.to_mont(&base), &d);
        if eq(&x, &m.one) || eq(&x, &minus_one) {
            continue;
        }
        let mut witness = true;
        for _ in 1..s {
            x = m.mul(&x, &x);
            if eq(&x, &minus_one) {
                witness = false;
                break;
            }
        }
        if witness {
            return false;
        }
    }
    true
}

/// HashToPrime under a caller-chosen domain separation tag.
pub(crate) fn hash_to_prime_dst(dst: &[u8], t: u64, x: &[u8], y: &[u8]) -> Result<Limbs<PL>> {
    for ctr in 0u32..65_536 {
        let mut h = Sha256::new();
        h.update(dst);
        h.update(ctr.to_be_bytes());
        h.update(t.to_be_bytes());
        h.update(x);
        h.update(y);
        let mut c: Limbs<PL> = from_be(&h.finalize());
        c[PL - 1] |= 1 << 63;
        c[0] |= 1;
        if probable_prime(&c) {
            return Ok(c);
        }
    }
    Err(Error::Invalid)
}


#[cfg(test)]
mod unit {
    use super::*;

    #[test]
    fn montgomery_round_trip_and_one() {
        let m = Monty::<32>::new(&crate::vdf_cg::P);
        let mut a = [0u64; 32];
        a[0] = 12345;
        a[7] = 0xdead_beef;
        assert_eq!(m.from_mont(&m.to_mont(&a)), a);
        assert_eq!(m.from_mont(&m.one)[0], 1);
    }

    #[test]
    fn small_prime_test() {
        // 2^255 + 95 is prime; 2^255 + 97 is divisible by 3.
        let mut p = [0u64; PL];
        p[PL - 1] = 1 << 63;
        p[0] = 95;
        assert!(probable_prime(&p));
        p[0] = 97;
        assert_eq!(rem_small(&p, 3), 0);
        assert!(!probable_prime(&p));
    }
}
