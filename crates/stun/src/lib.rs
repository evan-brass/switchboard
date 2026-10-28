#![no_std]
#![doc = include_str!("../README.md")]

use core::cell::Cell;
use zerocopy::{
	Immutable, IntoBytes, KnownLayout, SplitAt, TryFromBytes, Unaligned, network_endian::U16,
	try_transmute,
};

#[repr(u8)]
#[derive(
	Debug, Clone, Copy, PartialEq, Eq, KnownLayout, Immutable, Unaligned, TryFromBytes, IntoBytes,
)]
pub enum Class {
	Req(Request) = 0x00,
	Res(Response) = 0x01,
}

#[repr(u8)]
#[derive(
	Debug, Clone, Copy, PartialEq, Eq, KnownLayout, Immutable, Unaligned, TryFromBytes, IntoBytes,
)]
pub enum Request {
	Bind = 0x01,
	Allocate = 0x03,
	Refresh = 0x04,
	Send = 0x16,
	Recv = 0x17,
	AddPermission = 0x08,
	AssignChannel = 0x09,
}
impl From<Request> for Class {
	fn from(value: Request) -> Self {
		Self::Req(value)
	}
}
impl Request {
	#[inline]
	pub fn is_indication(&self) -> bool {
		(*self as u8 & 0x10) != 0
	}
	pub fn success(self) -> Response {
		assert!(!self.is_indication(), "Indications have no response.");
		try_transmute!(self as u8).unwrap()
	}
	pub fn failure(self) -> Response {
		assert!(!self.is_indication(), "Indications have no response.");
		try_transmute!(self as u8 | 0x10).unwrap()
	}
}

#[repr(u8)]
#[derive(
	Debug, Clone, Copy, PartialEq, Eq, KnownLayout, Immutable, Unaligned, TryFromBytes, IntoBytes,
)]
pub enum Response {
	Bound = 0x01,
	NotBound = 0x11,
	Allocated = 0x03,
	NotAllocated = 0x13,
	Refreshed = 0x04,
	NotRefreshed = 0x14,
	PermissionAdded = 0x08,
	PermissionNotAdded = 0x18,
	ChannelAssigned = 0x09,
	ChannelNotAssigned = 0x19,
}
impl From<Response> for Class {
	fn from(value: Response) -> Self {
		Self::Res(value)
	}
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, KnownLayout, Immutable, TryFromBytes, IntoBytes)]
pub enum Txid {
	Magic([u8; 12]) = u32::to_be(0x2112_A442),
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq, KnownLayout, TryFromBytes, IntoBytes, SplitAt)]
pub struct Stun {
	pub typ: Class,
	length: Cell<U16>,
	pub id: Txid,
	body: [[u8; 4]],
}
