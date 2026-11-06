#![no_std]
#![doc = include_str!("../README.md")]
#![allow(unused)]

pub use bytes;
use bytes::BufMut;
use core::{cell::Cell, convert::Infallible, fmt::Write, net::SocketAddr};
pub use zerocopy;
use zerocopy::{
	AlignedTryCastError, ConvertError, FromBytes, Immutable, IntoBytes, KnownLayout, SplitAt,
	TryFromBytes, Unaligned, network_endian::U16, try_transmute,
};

use crate::errcode::ErrCode;

pub mod errcode;
pub mod known;

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
impl Stun {
	pub const MAX_LENGTH: u16 = 0xffe0; // (((0xffff & ~0b11) - 20) - 8)
	#[inline]
	pub fn clear(&self) {
		self.length.set(U16::new(0));
	}
}

#[repr(C, packed)]
#[derive(KnownLayout, Immutable, Unaligned, FromBytes, SplitAt, IntoBytes)]
pub struct Attr {
	pub typ: u16,
	length: U16,
	pub value: [u8], // While writing: value is a buffer as big as the value could be (given u16 length requirements and buffer length inherited from Stun)
}
impl Attr {
	pub const MAX_LENGTH: u16 = Stun::MAX_LENGTH - 4;
	#[inline]
	pub fn padded_length(&self) -> u16 {
		let length = self.length.get();
		assert!(length <= Self::MAX_LENGTH, "Attribute length too large");
		(length + 3) & !3
	}
	#[inline]
	pub fn is_comprehension_required(&self) -> bool {
		self.typ & 0x8000 == 0
	}
}

pub struct AttrReader<'i> {
	target: &'i Stun,
}
pub struct AttrWriter<'i> {
	prefix: &'i Stun,
	target: &'i mut Attr,
}

impl Stun {
	pub fn frame_length(&self) -> usize {
		let length = self.length.get().get();
		if !length.is_multiple_of(4) {
			return usize::MAX;
		}
		20 + length as usize
	}
}
impl<'i> IntoIterator for &'i Stun {
	type Item = (&'i Stun, &'i Attr);
	type IntoIter = AttrReader<'i>;
	fn into_iter(self) -> Self::IntoIter {
		let length = self.length.get().get();
		let offset = if length.is_multiple_of(4) {
			usize::min(length as usize >> 2, self.body.len())
		} else {
			0
		};
		let (target, _) = self.split_at(offset).unwrap().via_into_bytes();
		target.clear(); // Zero the length since it is also our iterator offset.
		Self::IntoIter { target }
	}
}
impl<'i> Iterator for AttrReader<'i> {
	type Item = (&'i Stun, &'i Attr);
	fn next(&mut self) -> Option<Self::Item> {
		let length = self.target.length.get().get();
		if !length.is_multiple_of(4) {
			panic!("Corruption: Unaligned length");
		}
		let (prefix, rest) = self.target.split_at(length as usize >> 2)?.via_into_bytes();
		let max_attr_len = Attr::MAX_LENGTH.checked_sub(length)?;
		let attr = match Attr::ref_from_bytes(rest.as_flattened())
			.map_err(ConvertError::<Infallible, _, Infallible>::from)
		{
			Err(ConvertError::Validity(v)) => match v {},
			Err(ConvertError::Alignment(a)) => match a {},
			Err(ConvertError::Size(s)) => return None,
			Ok(v) => v,
		};
		let attr_length = attr.length.get();
		if attr_length > max_attr_len {
			return None;
		}
		let (attr, _) =
			Attr::ref_from_prefix_with_elems(rest.as_flattened(), attr_length as usize).ok()?;

		// Increment the Stun length past this attribute
		prefix.length.update(|l| l + 4 + attr.padded_length());

		Some((prefix, attr))
	}
}

impl Stun {
	pub fn append(&mut self) -> AttrWriter<'_> {
		let length = self.length.get().get();
		if !length.is_multiple_of(4) {
			panic!("Corruption: Unaligned length");
		}
		let offset = length as usize >> 2;
		let Some((prefix, free_space)) = self.split_at_mut(offset).map(|s| s.via_into_bytes())
		else {
			panic!("Corruption: Length exceeds body");
		};
		let Some(max_attr_length) = Attr::MAX_LENGTH.checked_sub(length) else {
			panic!("Can't append any more attributes: max length reached");
		};
		if free_space.len() == 0 {
			// Stun messages are mostly fixed size (USERNAME and DATA being the main reachable exceptions)
			panic!("Can't append any more attributes: buffer exhausted");
		}
		let max_value = usize::min(max_attr_length as usize, size_of_val(free_space) - 4);
		let target =
			Attr::mut_from_bytes_with_elems(free_space.as_flattened_mut(), max_value).unwrap();
		target.length.set(0);

		AttrWriter { prefix, target }
	}
}
impl Drop for AttrWriter<'_> {
	fn drop(&mut self) {
		let length = self.target.length.get();
		let padded_length = (length + 3) & !3;

		// Zero the padding bytes
		self.target.value[length as usize..padded_length as usize].fill(0);

		// Advance the Stun message's length
		self.prefix
			.length
			.update(|s| U16::new(s.get() + 4 + padded_length));
	}
}
impl AttrWriter<'_> {
	pub(crate) fn available(&mut self) -> &mut [u8] {
		// There should be no overflow checks
		let length = self.target.length.get() as usize;
		&mut self.target.value[length..]
	}
}
unsafe impl BufMut for AttrWriter<'_> {
	fn remaining_mut(&self) -> usize {
		let length = self.target.length.get() as usize;
		self.target.value.len() - length
	}
	unsafe fn advance_mut(&mut self, cnt: usize) {
		self.target.length += cnt as u16;
	}
	fn chunk_mut(&mut self) -> &mut bytes::buf::UninitSlice {
		bytes::buf::UninitSlice::new(self.available())
	}
}
impl Write for AttrWriter<'_> {
	fn write_str(&mut self, s: &str) -> core::fmt::Result {
		if s.len() > self.remaining_mut() {
			return Err(core::fmt::Error);
		}
		self.put_slice(s.as_bytes());
		Ok(())
	}
}
impl AttrWriter<'_> {
	pub fn put_typ(&mut self, typ: u16) -> &mut Self {
		self.target.typ = typ;
		self
	}
	pub fn put_errorcode(&mut self, code: ErrCode) -> &mut Self {
		self.put_slice(errcode::ErrorCode::from(code).as_bytes());
		self
	}
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

#[repr(u8)]
#[derive(
	Debug, Clone, Copy, PartialEq, Eq, KnownLayout, Immutable, Unaligned, TryFromBytes, IntoBytes,
)]
pub enum Transport {
	Udp = 17,
}
#[repr(C, align(4))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, KnownLayout, Immutable, TryFromBytes, IntoBytes)]
pub struct RequestedTransport {
	pub proto: Transport,
	pad1: [u8; 3],
}
impl From<Transport> for RequestedTransport {
	fn from(proto: Transport) -> Self {
		Self {
			proto,
			pad1: [0; 3],
		}
	}
}
