#![no_std]
#![doc = include_str!("../README.md")]

use bytes::BufMut;
use core::{cell::Cell, fmt::Write, net::SocketAddr};
use zerocopy::{
	FromBytes, Immutable, IntoBytes, KnownLayout, SplitAt, TryFromBytes, Unaligned,
	network_endian::U16, try_transmute,
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

#[repr(C, align(4))]
#[derive(Debug, PartialEq, Eq, KnownLayout, Immutable, FromBytes, SplitAt)]
pub struct Attr {
	pub typ: u16,
	length: U16,
	pub value: [u8], // Value may be longer than length while writing
}

pub struct AttrReader<'i> {
	target: &'i Stun,
}
pub struct AttrWriter<'i> {
	prefix: &'i Stun,
	target: &'i mut Attr,
}

impl<'i> IntoIterator for &'i Stun {
	type Item = (&'i Stun, &'i Attr);
	type IntoIter = AttrReader<'i>;
	fn into_iter(self) -> Self::IntoIter {
		// TODO: Trim the stun message
		// TODO: Zero the length since it becomes the offset we use to iterate the attributes
		todo!();
	}
}
impl<'i> Iterator for AttrReader<'i> {
	type Item = (&'i Stun, &'i Attr);
	fn next(&mut self) -> Option<Self::Item> {
		let offset = self.target.length.get().get();
		// TODO: Split the target Stun reference at the offset
		// TODO: Read an Attr from the prefix, then trim it to it's length
		// TODO: Increment the offset/length past the attribute
		todo!()
	}
}

impl Drop for AttrWriter<'_> {
	fn drop(&mut self) {
		// TODO: Once the attribute has its final length, zero the Attribute's padding and increment the Stun's offset/length
		todo!()
	}
}
unsafe impl BufMut for AttrWriter<'_> {
	fn remaining_mut(&self) -> usize {
		todo!()
	}
	unsafe fn advance_mut(&mut self, cnt: usize) {
		todo!()
	}
	fn chunk_mut(&mut self) -> &mut bytes::buf::UninitSlice {
		todo!()
	}
}
impl Write for AttrWriter<'_> {
	fn write_str(&mut self, s: &str) -> core::fmt::Result {
		todo!()
	}
}
impl AttrWriter<'_> {
	// BufMut extensions for STUN specific stuff
	pub fn put_fingerprint(&mut self) {
		todo!()
	}
	pub fn put_integrity_sha1(&mut self) {
		todo!()
	}
	pub fn put_address(&mut self, addr: SocketAddr) {
		todo!()
	}
}
