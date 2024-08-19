use ipnet::{Ipv4Net, Ipv6Net};
use num_traits::{PrimInt, Zero};

pub trait Prefix: Sized {
    type R: PrimInt + Zero;

    fn repr(&self) -> Self::R;

    fn zero() -> Self;

    fn prefix_len(&self) -> u8;

    fn equal(&self, other: &Self) -> bool;

    fn is_bit_set(&self, bit: u8) -> bool;

    fn contains(&self, other: &Self) -> bool;

    fn common_prefix(&self, other: &Self) -> Self;
}

fn mask_from_prefix_len<R>(len: u8) -> R
where
    R: PrimInt + Zero,
{
    if len as u32 == R::zero().count_zeros() {
        !R::zero()
    } else if len == 0 {
        R::zero()
    } else {
        !((!R::zero()) >> len as usize)
    }
}

impl Prefix for Ipv4Net {
    type R = u32;

    fn repr(&self) -> Self::R {
        self.addr().into()
    }

    fn zero() -> Self {
        Default::default()
    }

    fn prefix_len(&self) -> u8 {
        self.prefix_len()
    }

    fn equal(&self, other: &Self) -> bool {
        self == other
    }

    fn is_bit_set(&self, bit: u8) -> bool {
        let offset = bit / 8;
        let shift = 7 - (bit % 8);
        let octets = self.addr().octets();
        (octets[offset as usize] >> shift) & 0x1 == 0x1
    }

    fn contains(&self, other: &Self) -> bool {
        self.contains(other)
    }

    fn common_prefix(&self, other: &Self) -> Self {
        let a = self.repr();
        let b = other.repr();
        let len = ((a ^ b).leading_zeros() as u8)
            .min(self.prefix_len())
            .min(other.prefix_len());
        let repr = a & mask_from_prefix_len::<Self::R>(len);
        Self::new(repr.into(), len).unwrap()
    }
}

impl Prefix for Ipv6Net {
    type R = u128;

    fn repr(&self) -> Self::R {
        self.addr().into()
    }

    fn zero() -> Self {
        Default::default()
    }

    fn prefix_len(&self) -> u8 {
        self.prefix_len()
    }

    fn equal(&self, other: &Self) -> bool {
        self == other
    }

    fn is_bit_set(&self, bit: u8) -> bool {
        let offset = bit / 8;
        let shift = 7 - (bit % 8);
        let octets = self.addr().octets();
        (octets[offset as usize] >> shift) & 0x1 == 0x1
    }

    fn contains(&self, other: &Self) -> bool {
        self.contains(other)
    }

    fn common_prefix(&self, other: &Self) -> Self {
        let a = self.repr();
        let b = other.repr();
        let len = ((a ^ b).leading_zeros() as u8)
            .min(self.prefix_len())
            .min(other.prefix_len());
        let repr = a & mask_from_prefix_len::<Self::R>(len);
        Self::new(repr.into(), len).unwrap()
    }
}
