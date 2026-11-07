use core::{
	array::from_fn,
	marker::PhantomData,
	net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6},
};

use zerocopy::{
	Immutable, IntoBytes, KnownLayout, TryFromBytes, Unaligned, transmute, transmute_ref,
	try_transmute,
};

use crate::Txid;

pub trait Version {
	type Family: IntoBytes;
}
#[repr(u8)]
#[derive(
	Debug, Clone, Copy, PartialEq, Eq, KnownLayout, Immutable, Unaligned, TryFromBytes, IntoBytes,
)]
pub enum IPv6Family {
	Tag = 0x02,
}
impl Version for [u8; 16] {
	type Family = IPv6Family;
}
#[repr(u8)]
#[derive(
	Debug, Clone, Copy, PartialEq, Eq, KnownLayout, Immutable, Unaligned, TryFromBytes, IntoBytes,
)]
pub enum IPv4Family {
	Tag = 0x01,
}
impl Version for [u8; 4] {
	type Family = IPv4Family;
}

pub trait Xored {
	type Other: Xored;
}
pub struct Xor;
pub struct NotXor;
impl Xored for Xor {
	type Other = NotXor;
}
impl Xored for NotXor {
	type Other = Xor;
}

#[repr(C)]
#[derive(
	Debug, PartialEq, Eq, Clone, Copy, KnownLayout, Immutable, Unaligned, TryFromBytes, IntoBytes,
)]
pub struct Addr<X: Xored, O: Version> {
	xor: PhantomData<X>,
	pad1: u8,
	family: O::Family,
	port: [u8; 2],
	octets: O,
}
impl<X, const N: usize> Addr<X, [u8; N]>
where
	X: Xored,
	[u8; N]: Version,
{
	pub fn xor(mut self, id: &Txid) -> Addr<X::Other, [u8; N]> {
		let xor_bytes: &[u8; 16] = transmute_ref!(id);
		let port = from_fn(|i| self.port[i] ^ xor_bytes[i]);
		let octets = from_fn(|i| self.octets[i] ^ xor_bytes[i]);
		Addr {
			xor: PhantomData,
			pad1: self.pad1,
			family: self.family,
			port,
			octets,
		}
	}
}

impl From<SocketAddrV4> for Addr<NotXor, [u8; 4]> {
	fn from(value: SocketAddrV4) -> Self {
		Self {
			xor: PhantomData,
			pad1: 0,
			family: IPv4Family::Tag,
			port: value.port().to_be_bytes(),
			octets: value.ip().octets(),
		}
	}
}
impl From<SocketAddrV6> for Addr<NotXor, [u8; 16]> {
	fn from(value: SocketAddrV6) -> Self {
		Self {
			xor: PhantomData,
			pad1: 0,
			family: IPv6Family::Tag,
			port: value.port().to_be_bytes(),
			octets: value.ip().octets(),
		}
	}
}

impl From<Addr<NotXor, [u8; 4]>> for SocketAddrV4 {
	fn from(value: Addr<NotXor, [u8; 4]>) -> Self {
		Self::new(
			Ipv4Addr::from_octets(value.octets),
			u16::from_be_bytes(value.port),
		)
	}
}
impl From<Addr<NotXor, [u8; 16]>> for SocketAddrV6 {
	fn from(value: Addr<NotXor, [u8; 16]>) -> Self {
		Self::new(
			Ipv6Addr::from_octets(value.octets),
			u16::from_be_bytes(value.port),
			0,
			0,
		)
	}
}
