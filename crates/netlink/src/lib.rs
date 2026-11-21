#![no_std]
#![doc = include_str!("../README.md")]
#![allow(non_camel_case_types)]

#[cfg(any(feature = "socket", test))]
extern crate std;

pub mod netfilter;

pub use bytes;
use bytes::BufMut;
use core::{fmt, fmt::Write, marker::PhantomData};
pub use zerocopy;
use zerocopy::{
	FromBytes, Immutable, IntoBytes, KnownLayout, TryFromBytes, Unaligned,
	native_endian::{I32, U16, U32},
};

pub mod known;
#[cfg(feature = "socket")]
mod socket;
#[cfg(feature = "socket")]
pub use socket::Netlink;

/// NLMSG_ALIGN / NLA_ALIGN
#[inline]
pub const fn align4(n: usize) -> usize {
	(n + 3) & !3
}

/// Describes the family header(s) of a netlink protocol.
pub trait Protocol {
	/// Typically an enum over the protocol's family headers (borrowed from the message)
	type Header<'a>;
	/// Pick and view the family header for a (non-control) message type.
	/// Returns the header and its unpadded size; attributes start after the padded size.
	/// Return None for unknown types or truncated headers.
	fn header<'a>(typ: u16, payload: &'a [u8]) -> Option<(Self::Header<'a>, usize)>;
}

/// No family header: the whole payload is attributes
pub struct Raw;
impl Protocol for Raw {
	type Header<'a> = ();
	fn header(_: u16, _: &[u8]) -> Option<((), usize)> {
		Some(((), 0))
	}
}

/// Every message type shares the same family header (e.g. genlmsghdr, nfgenmsg)
pub struct Single<H>(PhantomData<H>);
impl<H: TryFromBytes + KnownLayout + Immutable + Unaligned + 'static> Protocol for Single<H> {
	type Header<'a> = &'a H;
	fn header(_: u16, payload: &[u8]) -> Option<(&H, usize)> {
		view(payload)
	}
}

/// Helper for Protocol impls: view a family header at the start of the payload
pub fn view<H: TryFromBytes + KnownLayout + Immutable + Unaligned>(
	payload: &[u8],
) -> Option<(&H, usize)> {
	let (header, _) = H::try_ref_from_prefix(payload).ok()?;
	Some((header, size_of::<H>()))
}

/// A netlink message laid over a buffer (no alignment requirement).
///
/// `body` spans the rest of the buffer, not just this message: while reading, the buffer may
/// contain further messages (see [`nlmsghdr::frame_length`]); while writing, it is the free space
/// that attributes are appended into.
#[repr(C)]
#[derive(KnownLayout, Immutable, Unaligned, FromBytes, IntoBytes)]
pub struct nlmsghdr<P: Protocol = Raw> {
	len: U32,
	pub typ: U16,
	pub flags: U16,
	pub seq: U32,
	pub pid: U32,
	proto: PhantomData<P>,
	body: [u8],
}
impl<P: Protocol> fmt::Debug for nlmsghdr<P> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("nlmsghdr")
			.field("len", &self.len.get())
			.field("typ", &self.typ.get())
			.field("flags", &self.flags.get())
			.field("seq", &self.seq.get())
			.field("pid", &self.pid.get())
			.finish_non_exhaustive()
	}
}

/// Payload of an NLMSG_ERROR message: the error code followed by the header of the request that caused it.
#[repr(C)]
#[derive(
	Debug, Clone, Copy, PartialEq, Eq, KnownLayout, Immutable, Unaligned, FromBytes, IntoBytes,
)]
pub struct nlmsgerr {
	/// 0 for an ACK, otherwise a negative errno
	pub error: I32,
	pub msg_len: U32,
	pub msg_typ: U16,
	pub msg_flags: U16,
	pub msg_seq: U32,
	pub msg_pid: U32,
}

/// The decoded contents of a message
#[derive(Debug)]
pub enum Body<'a, P: Protocol> {
	/// A protocol message: its family header and attributes
	Msg(P::Header<'a>, Attrs<'a>),
	/// NLMSG_ERROR with error == 0 (extended ack attributes, if any)
	Ack(Attrs<'a>),
	/// NLMSG_DONE with error == 0: end of a dump (extended ack attributes, if any)
	Done(Attrs<'a>),
	/// NLMSG_ERROR or NLMSG_DONE with error != 0
	Error(Error<'a>),
	/// NOOP / OVERRUN / unrecognized type / truncated header: inspect the message yourself
	Unknown,
}

/// An error reported by the kernel
#[derive(Clone)]
pub struct Error<'a> {
	/// Negative errno
	pub code: i32,
	/// The quoted request header (None if the error came from NLMSG_DONE)
	pub request: Option<&'a nlmsgerr>,
	/// Extended ack attributes (`known::NLMSGERR_ATTR_*`)
	pub ext_ack: Attrs<'a>,
}
impl<'a> Error<'a> {
	/// NLMSGERR_ATTR_MSG: the kernel's human readable error message
	pub fn message(&self) -> Option<&'a str> {
		let attr = self
			.ext_ack
			.clone()
			.find(|a| a.typ() == known::NLMSGERR_ATTR_MSG)?;
		let value = attr.value.strip_suffix(&[0]).unwrap_or(&attr.value);
		str::from_utf8(value).ok()
	}
}
impl fmt::Debug for Error<'_> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("Error")
			.field("code", &self.code)
			.field("request", &self.request)
			.field("message", &self.message())
			.finish()
	}
}

impl<P: Protocol> nlmsghdr<P> {
	pub const HDR_LEN: u32 = 16;

	/// Unpadded message length (from the header)
	#[inline]
	pub fn len(&self) -> u32 {
		self.len.get()
	}

	/// Bytes from the start of this message to the start of the next one.
	/// Returns usize::MAX if the header's length is invalid.
	/// If `frame_length() < received`, the buffer contains more messages: they start at `buf[frame_length()..]`.
	pub fn frame_length(&self) -> usize {
		if self.len() < Self::HDR_LEN {
			return usize::MAX;
		}
		align4(self.len() as usize)
	}

	/// The bytes following the header, up to the message's length (clamped to the buffer)
	pub fn payload(&self) -> &[u8] {
		let len = (self.len() as usize).saturating_sub(Self::HDR_LEN as usize);
		&self.body[..usize::min(len, self.body.len())]
	}

	/// View this message as a different protocol
	pub fn retype<Q: Protocol>(&self) -> &nlmsghdr<Q> {
		nlmsghdr::<Q>::ref_from_bytes(self.as_bytes()).unwrap()
	}
	pub fn retype_mut<Q: Protocol>(&mut self) -> &mut nlmsghdr<Q> {
		nlmsghdr::<Q>::mut_from_bytes(self.as_mut_bytes()).unwrap()
	}

	/// Decode the message: control messages (ACK / DONE / errors) are handled here, everything else goes to `P`.
	pub fn body(&self) -> Body<'_, P> {
		let payload = self.payload();
		let flags = self.flags.get();
		let tlvs = |start: usize| {
			if flags & known::NLM_F_ACK_TLVS != 0 {
				Attrs::new(payload.get(start..).unwrap_or(&[]))
			} else {
				Attrs::new(&[])
			}
		};
		match self.typ.get() {
			known::NLMSG_ERROR => {
				let Ok((err, _)) = nlmsgerr::ref_from_prefix(payload) else {
					return Body::Unknown;
				};
				// Unless capped, the request's payload is echoed between nlmsgerr and the TLVs
				let echoed = if flags & known::NLM_F_CAPPED != 0 {
					0
				} else {
					align4(err.msg_len.get().saturating_sub(Self::HDR_LEN) as usize)
				};
				let ext_ack = tlvs(size_of::<nlmsgerr>() + echoed);
				match err.error.get() {
					0 => Body::Ack(ext_ack),
					code => Body::Error(Error {
						code,
						request: Some(err),
						ext_ack,
					}),
				}
			}
			known::NLMSG_DONE => {
				let code = I32::read_from_prefix(payload).map_or(0, |(c, _)| c.get());
				let ext_ack = tlvs(size_of::<I32>());
				match code {
					0 => Body::Done(ext_ack),
					code => Body::Error(Error {
						code,
						request: None,
						ext_ack,
					}),
				}
			}
			typ if typ < known::NLMSG_MIN_TYPE => Body::Unknown,
			typ => match P::header(typ, payload) {
				Some((header, size)) => Body::Msg(
					header,
					Attrs::new(payload.get(align4(size)..).unwrap_or(&[])),
				),
				None => Body::Unknown,
			},
		}
	}
}

// Writing
impl<P: Protocol> nlmsghdr<P> {
	/// Reset the message to an empty payload (typ, flags, seq, pid are left alone)
	#[inline]
	pub fn clear(&mut self) {
		self.len.set(Self::HDR_LEN);
	}

	/// Append raw bytes to the payload (padded to 4 bytes). Use this for the family header before appending attributes.
	pub fn put_header<H: IntoBytes + Immutable + ?Sized>(&mut self, header: &H) -> &mut Self {
		let bytes = header.as_bytes();
		let (start, free) = Self::free_space(self.len.get(), &mut self.body);
		let padded = align4(bytes.len());
		assert!(padded <= free.len(), "Can't add header: buffer exhausted");
		free[..bytes.len()].copy_from_slice(bytes);
		free[bytes.len()..padded].fill(0);
		self.len.set(start + padded as u32);
		self
	}

	/// Start a new attribute at the end of the message. Committed to the message's length on Drop.
	pub fn append(&mut self) -> AttrWriter<'_> {
		let (base, free) = Self::free_space(self.len.get(), &mut self.body);
		AttrWriter::new(ParentLen::Msg(&mut self.len), base, free)
	}

	/// (Aligned message length, free space after it)
	fn free_space(len: u32, body: &mut [u8]) -> (u32, &mut [u8]) {
		let Some(len) = len.checked_sub(Self::HDR_LEN) else {
			panic!("Corruption: message length smaller than header");
		};
		let offset = align4(len as usize);
		// Leave the free space a multiple of 4 so attribute padding always fits
		let end = body.len() & !3;
		let Some(free) = body.get_mut(offset..end) else {
			panic!("Corruption: message length exceeds buffer");
		};
		(Self::HDR_LEN + offset as u32, free)
	}
}

/// A netlink attribute (TLV). `len` is unpadded and includes the 4 byte header.
#[repr(C)]
#[derive(KnownLayout, Immutable, Unaligned, FromBytes, IntoBytes)]
pub struct nlattr {
	len: U16,
	typ: U16,
	pub value: [u8],
}
impl nlattr {
	pub const HDR_LEN: u16 = 4;
	/// Largest value we'll write such that the padded attribute still fits in a u16
	const MAX_VALUE: usize = 0xFFFC - Self::HDR_LEN as usize;

	/// Attribute type with the NESTED / NET_BYTEORDER flags masked off
	#[inline]
	pub fn typ(&self) -> u16 {
		self.typ.get() & known::NLA_TYPE_MASK
	}
	#[inline]
	pub fn raw_typ(&self) -> u16 {
		self.typ.get()
	}
	#[inline]
	pub fn is_nested(&self) -> bool {
		self.typ.get() & known::NLA_F_NESTED != 0
	}
	#[inline]
	pub fn is_net_byteorder(&self) -> bool {
		self.typ.get() & known::NLA_F_NET_BYTEORDER != 0
	}
	/// Iterate the attributes nested in this attribute's value. (Doesn't check NLA_F_NESTED since not all protocols set it.)
	#[inline]
	pub fn nested(&self) -> Attrs<'_> {
		Attrs::new(&self.value)
	}
}

/// Iterator over a run of attributes. Stops at the first malformed / truncated attribute.
#[derive(Debug, Clone)]
pub struct Attrs<'i> {
	rest: &'i [u8],
}
impl<'i> Attrs<'i> {
	pub fn new(bytes: &'i [u8]) -> Self {
		Self { rest: bytes }
	}
	/// Bytes not yet consumed (non-empty after iteration ends means trailing garbage / truncation)
	pub fn remaining(&self) -> &'i [u8] {
		self.rest
	}
}
impl<'i> Iterator for Attrs<'i> {
	type Item = &'i nlattr;
	fn next(&mut self) -> Option<Self::Item> {
		let (len, _) = U16::read_from_prefix(self.rest).ok()?;
		let len = len.get() as usize;
		if len < nlattr::HDR_LEN as usize {
			return None;
		}
		let (attr, _) =
			nlattr::ref_from_prefix_with_elems(self.rest, len - nlattr::HDR_LEN as usize).ok()?;
		let advance = usize::min(align4(len), self.rest.len());
		self.rest = &self.rest[advance..];
		Some(attr)
	}
}

enum ParentLen<'i> {
	Msg(&'i mut U32),
	Attr(&'i mut U16),
}

/// Writes one attribute. On Drop: pads the value and commits the new length to the parent (message or nesting attribute).
pub struct AttrWriter<'i> {
	parent: ParentLen<'i>,
	/// Parent's length up to the start of this attribute
	base: u32,
	/// While writing: value is a buffer as big as the value could be
	target: &'i mut nlattr,
}
impl<'i> AttrWriter<'i> {
	fn new(parent: ParentLen<'i>, base: u32, free: &'i mut [u8]) -> Self {
		let Some(capacity) = free.len().checked_sub(nlattr::HDR_LEN as usize) else {
			panic!("Can't append any more attributes: buffer exhausted");
		};
		// Keep capacity a multiple of 4 so padding always fits
		let capacity = usize::min(capacity, nlattr::MAX_VALUE) & !3;
		let (target, _) = nlattr::mut_from_prefix_with_elems(free, capacity).unwrap();
		target.len.set(nlattr::HDR_LEN);
		target.typ.set(0);
		Self {
			parent,
			base,
			target,
		}
	}
	#[inline]
	fn value_len(&self) -> usize {
		(self.target.len.get() - nlattr::HDR_LEN) as usize
	}

	/// Set the attribute type. Flags (NLA_F_NESTED, NLA_F_NET_BYTEORDER) may be included and are preserved.
	pub fn put_typ(&mut self, typ: u16) -> &mut Self {
		let flags = self.target.typ.get() & !known::NLA_TYPE_MASK;
		self.target.typ.set(typ | flags);
		self
	}

	/// Start a nested attribute at the end of this attribute's value. Marks this attribute NLA_F_NESTED.
	pub fn nest(&mut self) -> AttrWriter<'_> {
		self.target
			.typ
			.set(self.target.typ.get() | known::NLA_F_NESTED);
		let len = self.value_len();
		let offset = align4(len);
		self.target.value[len..offset].fill(0);
		let parent = ParentLen::Attr(&mut self.target.len);
		let free = &mut self.target.value[offset..];
		AttrWriter::new(parent, (nlattr::HDR_LEN as usize + offset) as u32, free)
	}
}
impl Drop for AttrWriter<'_> {
	fn drop(&mut self) {
		let len = self.value_len();
		let padded = align4(len);
		// Zero the padding bytes
		self.target.value[len..padded].fill(0);

		let total = self.base + nlattr::HDR_LEN as u32 + padded as u32;
		match &mut self.parent {
			ParentLen::Msg(l) => l.set(total),
			ParentLen::Attr(l) => l.set(total as u16),
		}
	}
}
unsafe impl BufMut for AttrWriter<'_> {
	fn remaining_mut(&self) -> usize {
		self.target.value.len() - self.value_len()
	}
	unsafe fn advance_mut(&mut self, cnt: usize) {
		let len = self.target.len.get();
		self.target.len.set(len + cnt as u16);
	}
	fn chunk_mut(&mut self) -> &mut bytes::buf::UninitSlice {
		let len = self.value_len();
		bytes::buf::UninitSlice::new(&mut self.target.value[len..])
	}
}
impl Write for AttrWriter<'_> {
	fn write_str(&mut self, s: &str) -> fmt::Result {
		if s.len() > self.remaining_mut() {
			return Err(fmt::Error);
		}
		self.put_slice(s.as_bytes());
		Ok(())
	}
}

#[cfg(test)]
mod tests;
