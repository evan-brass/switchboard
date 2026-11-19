use core::net::SocketAddr;

use zerocopy::{
	AlignmentError, ConvertError, Immutable, IntoBytes, KnownLayout, TryFromBytes, ValidityError,
	big_endian::{U16, U32, U64},
	try_transmute,
};

use crate::{
	Attr, Transport, Txid,
	addr::{Addr, Family, IPv6Family, NotXor, Xor, Xored},
	errcode::ErrorCode,
};

#[repr(u16)]
#[non_exhaustive]
#[derive(Debug, KnownLayout, Immutable, TryFromBytes)]
pub enum Fixed {
	OldMappedAddress(LengthedAddr<NotXor>) = u16::to_be(0x0001),
	Username {
		len: U16,
		// username: str.
	} = u16::to_be(0x0006),
	MessageIntegritySha1 {
		len: Length20,
		mac: [u8; 20],
	} = u16::to_be(0x0008),
	ErrorCode {
		/// len should be >= size_of::<ErrorCode>()
		len: [u8; 2],
		code: ErrorCode,
		// reason: str,
	} = u16::to_be(0x0009),
	UnknownAttributes {
		/// len should be a multiple of 2
		len: [u8; 2],
		// unk: [u16]
	} = u16::to_be(0x000A),
	ChannelNumber {
		len: Length4,
		channel: U16,
		pad1: [u8; 2],
	} = u16::to_be(0x000C),
	Lifetime {
		len: Length4,
		lifetime: U32,
	} = u16::to_be(0x000D),
	PeerAddress(LengthedAddr<Xor>) = u16::to_be(0x0012),
	Data {
		len: U16,
		// data: [u8]
	} = u16::to_be(0x0013),
	Realm {
		len: U16,
		// realm: str
	} = u16::to_be(0x0014),
	Nonce {
		len: U16,
		// nonce: str
	} = u16::to_be(0x0015),
	RelayedAddress(LengthedAddr<Xor>) = u16::to_be(0x0016),
	RequestedAddressFamily {
		len: Length4,
		family: Family,
		pad1: [u8; 3],
	} = u16::to_be(0x0017),
	EvenPort {
		len: Length1,
		reserve: u8, // I'm not gonna fuck with the bitfield, just don't use this.
	} = u16::to_be(0x0018),
	RequestedTransport {
		len: Length4,
		transport: Transport,
		pad1: [u8; 3],
	} = u16::to_be(0x0019),
	DontFragment {
		len: Length0,
	} = u16::to_be(0x001A),
	MappedAddress(LengthedAddr<Xor>) = u16::to_be(0x0020),
	ReservationToken {
		len: Length8,
		token: [u8; 8],
	} = u16::to_be(0x0022),
	Priority {
		len: Length4,
		priority: U32,
	} = u16::to_be(0x0024),
	UseCandidate {
		len: Length0,
	} = u16::to_be(0x0025),
	AdditionalAddressFamily {
		len: Length4,
		family: IPv6Family,
		pad1: [u8; 3],
	} = u16::to_be(0x8000),
	AlternateDomain {
		len: U16,
		// domain: str
	} = u16::to_be(0x8003),
	Icmp {
		len: Length8,
		type1: u8,
		code1: u8,
		type2: u8,
		code2: u8,
		data: U32,
	} = u16::to_be(0x8004),
	Software {
		len: U16,
		// software: str
	} = u16::to_be(0x8022),
	AlternateServer(LengthedAddr<NotXor>) = u16::to_be(0x8023),
	Fingerprint {
		len: Length4,
		csum: [u8; 4],
	} = u16::to_be(0x8028),
	IceControlled {
		len: Length8,
		tiebreaker: U64,
	} = u16::to_be(0x8029),
	IceControlling {
		len: Length8,
		tiebreaker: U64,
	} = u16::to_be(0x802A),
}

impl Fixed {
	pub fn try_read(attr: &Attr) -> Result<Self, ValidityError<[u8; size_of::<Self>()], Self>> {
		let attr = attr.as_bytes();
		let mut space = [0; size_of::<Self>()];
		let end = usize::min(space.len(), attr.len());
		space[..end].copy_from_slice(&attr[..end]);

		// NOTE: try_transmute only returns validity errors, so it must realign the [u8; N] -> align(2+)
		try_transmute!(space)
	}
}

#[repr(u16)]
#[derive(Debug, KnownLayout, Immutable, TryFromBytes)]
pub enum LengthedAddr<X: Xored> {
	IPv4(Addr<X, [u8; 4]>) = u16::to_be(8),
	IPv6(Addr<X, [u8; 16]>) = u16::to_be(20),
}
impl<X: Xored> LengthedAddr<X> {
	pub fn xor(self, id: &Txid) -> LengthedAddr<X::Other> {
		match self {
			Self::IPv4(v4) => LengthedAddr::IPv4(v4.xor(id)),
			Self::IPv6(v6) => LengthedAddr::IPv6(v6.xor(id)),
		}
	}
}
impl From<LengthedAddr<NotXor>> for SocketAddr {
	fn from(value: LengthedAddr<NotXor>) -> Self {
		match value {
			LengthedAddr::IPv4(v4) => Self::V4(v4.into()),
			LengthedAddr::IPv6(v6) => Self::V6(v6.into()),
		}
	}
}
// TODO: If Fixed can be used for writing, then this would become viable
// impl From<SocketAddr> for LengthedAddr<NotXor> {
// 	fn from(value: SocketAddr) -> Self {
// 		match value {
// 			SocketAddr::V4(v4) => Self::IPv4(v4.into()),
// 			SocketAddr::V6(v6) => Self::IPv6(v6.into()),
// 		}
// 	}
// }

#[repr(u16)]
#[derive(Debug, KnownLayout, Immutable, TryFromBytes, IntoBytes)]
pub enum Length0 {
	L = u16::to_be(0),
}
#[repr(u16)]
#[derive(Debug, KnownLayout, Immutable, TryFromBytes, IntoBytes)]
pub enum Length1 {
	L = u16::to_be(1),
}
#[repr(u16)]
#[derive(Debug, KnownLayout, Immutable, TryFromBytes, IntoBytes)]
pub enum Length4 {
	L = u16::to_be(4),
}
#[repr(u16)]
#[derive(Debug, KnownLayout, Immutable, TryFromBytes, IntoBytes)]
pub enum Length8 {
	L = u16::to_be(8),
}
#[repr(u16)]
#[derive(Debug, KnownLayout, Immutable, TryFromBytes, IntoBytes)]
pub enum Length20 {
	L = u16::to_be(20),
}
