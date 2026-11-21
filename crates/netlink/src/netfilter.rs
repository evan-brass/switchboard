use libc::{AF_INET, AF_INET6};
use zerocopy::{
	Immutable, IntoBytes, KnownLayout, TryFromBytes, Unaligned, transmute, try_transmute,
};

use crate::{Protocol, view};

// <linux/netfilter/nfnetlink.h>, <linux/netfilter/nfnetlink_conntrack.h>
pub const NFNL_SUBSYS_CTNETLINK: u16 = 1;
pub const IPCTNL_MSG_CT_NEW: u16 = 0;
pub const IPCTNL_MSG_CT_GET: u16 = 1;
pub const NFNETLINK_V0: u8 = 0;

pub const CTA_TUPLE_ORIG: u16 = 1;
pub const CTA_TUPLE_REPLY: u16 = 2;
pub const CTA_MARK: u16 = 8;

pub const CTA_TUPLE_IP: u16 = 1;
pub const CTA_TUPLE_PROTO: u16 = 2;

pub const CTA_IP_V4_SRC: u16 = 1;
pub const CTA_IP_V4_DST: u16 = 2;
pub const CTA_IP_V6_SRC: u16 = 3;
pub const CTA_IP_V6_DST: u16 = 4;

pub const CTA_PROTO_NUM: u16 = 1;
pub const CTA_PROTO_SRC_PORT: u16 = 2;
pub const CTA_PROTO_DST_PORT: u16 = 3;

#[repr(u8)]
#[derive(Debug, Clone, Copy, KnownLayout, Immutable, Unaligned, TryFromBytes, IntoBytes)]
pub enum Netfilter {
	Ct(CtOp) = 1,
}
#[repr(u8)]
#[derive(Debug, Clone, Copy, KnownLayout, Immutable, Unaligned, TryFromBytes, IntoBytes)]
pub enum CtOp {
	New = 0,
	Get = 1,
}
impl From<Netfilter> for u16 {
	fn from(value: Netfilter) -> Self {
		u16::from_ne_bytes(transmute!(value))
	}
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, KnownLayout, Immutable, Unaligned, TryFromBytes, IntoBytes)]
pub enum Family {
	IPv4 = AF_INET as u8,
	IPv6 = AF_INET6 as u8,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, KnownLayout, Immutable, Unaligned, TryFromBytes, IntoBytes)]
pub struct nfgenmsg {
	pub family: Family,
	pub ver: u8,
	pub pad1: [u8; 2],
}

impl Protocol for Netfilter {
	type Header<'a> = &'a nfgenmsg;
	fn header<'a>(typ: u16, payload: &'a [u8]) -> Option<(Self::Header<'a>, usize)> {
		let _: Self = try_transmute!(typ.to_ne_bytes()).ok()?;
		view(payload)
	}
}
