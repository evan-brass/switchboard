use socket2::{Domain, Protocol, Socket, Type};
use std::{ffi::c_int, io::Result};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, SplitAt};

#[repr(C, align(4))]
#[derive(Debug, PartialEq, Eq, KnownLayout, Immutable, FromBytes, IntoBytes, SplitAt)]
pub struct nlmsghdr {
	len: u32,
	typ: u16,
	flags: u16,
	pub seq: u32,
	pid: u32,
	body: [[u8; 4]],
}
#[repr(C, align(4))]
#[derive(Debug, PartialEq, Eq, KnownLayout, Immutable, FromBytes, IntoBytes)]
pub struct genlmsghdr {
	pub cmd: u8,
	version: u8,
	reserved: u16,
}
#[repr(C, align(4))]
#[derive(Debug, PartialEq, Eq, KnownLayout, Immutable, FromBytes, SplitAt)]
pub struct nlmsgerr {
	pub error: c_int,
	msg: nlmsghdr,
}
impl nlmsghdr {
	pub const MIN_LEN: u32 = 16;
	pub fn append(&mut self) -> AttrWriter<'_> {
		let current_len = u32::min(Self::MIN_LEN, self.len);
		// TODO: Is the length padded to 4 bytes?
		let offset = (current_len - Self::MIN_LEN) as usize / 4;
		let Some((prefix, rest)) = self.split_at_mut(offset).map(|s| s.via_into_bytes()) else {
			panic!("Corruption, buffer too small to add more attributes.");
		};
		let Ok(target) = nlattr::mut_from_bytes(rest.as_flattened_mut()) else {
			panic!("Corruption, buffer too small to add more attributes");
		};
		todo!()
	}
}

#[repr(C, align(4))]
#[derive(Debug, PartialEq, Eq, KnownLayout, Immutable, FromBytes, IntoBytes, SplitAt)]
pub struct nlattr {
	len: u16,
	pub typ: u16,
	body: [[u8; 4]],
}
impl nlattr {
	pub const MIN_LEN: u16 = 4;
	pub fn value(&self) -> &[u8] {
		// TODO: I didn't need
		todo!()
	}
	pub fn is_nested(&self) -> bool {
		(self.typ & 0x8000) != 0
	}
	pub fn nest(&mut self) -> NestedAttrWriter<'_> {
		// TODO: Split off the current length and put
		todo!();
	}
}

// TODO: Add Drop implementations for these that propagate the target's new length
// TODO: Implement BufMut and fmt::Write for these in the same way as the AttrWriter from Stun.
pub struct AttrWriter<'i> {
	prefix: &'i mut nlmsghdr,
	target: &'i mut nlattr,
}
pub struct NestedAttrWriter<'i> {
	prefix: &'i mut nlattr,
	target: &'i mut nlattr,
}

pub struct Netlink {
	sock: Socket,
	seq: u32,
}
impl Netlink {
	pub fn new(proto: i32) -> Result<Self> {
		let sock = Socket::new(
			Domain::from(libc::AF_NETLINK),
			Type::RAW,
			Some(Protocol::from(proto)),
		)?;

		Ok(Self { sock, seq: 0 })
	}
}
