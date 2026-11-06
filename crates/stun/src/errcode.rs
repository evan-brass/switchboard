use zerocopy::{Immutable, IntoBytes, KnownLayout, TryFromBytes, Unaligned};

#[repr(C, align(4))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, KnownLayout, Immutable, TryFromBytes, IntoBytes)]
pub struct ErrorCode {
	pad1: [u8; 2],
	pub code: ErrCode,
}
impl From<ErrCode> for ErrorCode {
	fn from(code: ErrCode) -> Self {
		Self { pad1: [0; 2], code }
	}
}

#[repr(u8)]
#[derive(
	Debug, Clone, Copy, PartialEq, Eq, KnownLayout, Immutable, Unaligned, TryFromBytes, IntoBytes,
)]
pub enum ErrCode {
	Redirect(RedirectErr) = 3,
	Client(ClientErr) = 4,
	Server(ServerErr) = 5,
}

#[repr(u8)]
#[derive(
	Debug, Clone, Copy, PartialEq, Eq, KnownLayout, Immutable, Unaligned, TryFromBytes, IntoBytes,
)]
pub enum RedirectErr {
	TryAlternate = 00,
}
impl From<RedirectErr> for ErrCode {
	fn from(value: RedirectErr) -> Self {
		Self::Redirect(value)
	}
}

#[repr(u8)]
#[derive(
	Debug, Clone, Copy, PartialEq, Eq, KnownLayout, Immutable, Unaligned, TryFromBytes, IntoBytes,
)]
pub enum ClientErr {
	BadRequest = 00,
	Unauthenticated = 01,
	Forbidden = 03,
	MobilityForbidden = 05,
	UnknownAttribute = 20,
	AllocationMismatch = 37,
	StaleNonce = 38,
	AddressFamilyNotSupported = 40,
	WrongCredentials = 41,
	UnsupportedTransportProtocol = 42,
	PeerAddressFamilyMismatch = 43,
	ConnectionAlreadyExists = 46,
	ConnectionTimeout = 47,
	AllocationQuotaReached = 86,
	RoleConflict = 87,
}
impl From<ClientErr> for ErrCode {
	fn from(value: ClientErr) -> Self {
		Self::Client(value)
	}
}

#[repr(u8)]
#[derive(
	Debug, Clone, Copy, PartialEq, Eq, KnownLayout, Immutable, Unaligned, TryFromBytes, IntoBytes,
)]
pub enum ServerErr {
	Fault = 00,
	InsuffiicientCapacity = 08,
}
impl From<ServerErr> for ErrCode {
	fn from(value: ServerErr) -> Self {
		Self::Server(value)
	}
}
