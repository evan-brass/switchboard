use crate::{known::*, *};
use zerocopy::{
	FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned, network_endian::U16 as BeU16,
};

// Stand-in for a wrapper crate's family header
#[repr(C)]
#[derive(Debug, PartialEq, Eq, KnownLayout, Immutable, Unaligned, FromBytes, IntoBytes)]
struct nfgenmsg {
	family: u8,
	version: u8,
	res_id: BeU16,
}
type Nf = Single<nfgenmsg>;

fn build(buf: &mut [u8]) -> usize {
	let msg = nlmsghdr::<Nf>::mut_from_bytes(buf).unwrap();
	msg.clear();
	msg.typ.set(0x0101);
	msg.flags.set(NLM_F_REQUEST | NLM_F_ACK);
	msg.seq.set(0);
	msg.pid.set(0);
	msg.put_header(&nfgenmsg {
		family: 2,
		version: 0,
		res_id: 0.into(),
	});
	{
		let mut orig = msg.append();
		orig.put_typ(1);
		orig.nest()
			.put_typ(1)
			.nest()
			.put_typ(1)
			.put_slice(&[192, 168, 0, 1]);
		orig.nest().put_typ(2).nest().put_typ(1).put_u8(17);
	}
	write!(msg.append().put_typ(9), "abc").unwrap();
	msg.len() as usize
}

#[cfg(target_endian = "little")]
const EXPECTED: [u8; 56] = [
	56, 0, 0, 0, 0x01, 0x01, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, // nlmsghdr
	2, 0, 0, 0, // nfgenmsg
	28, 0, 1, 0x80, // orig (nested)
	12, 0, 1, 0x80, // ip (nested)
	8, 0, 1, 0, 192, 168, 0, 1, // v4 src
	12, 0, 2, 0x80, // proto (nested)
	5, 0, 1, 0, 17, 0, 0, 0, // proto num + padding
	7, 0, 9, 0, b'a', b'b', b'c', 0, // string + padding
];

#[test]
#[cfg(target_endian = "little")]
fn encode() {
	let mut buf = [0xAAu8; 256];
	let len = build(&mut buf);
	assert_eq!(&buf[..len], &EXPECTED);
	// Unaligned buffers work too
	let len = build(&mut buf[1..]);
	assert_eq!(&buf[1..len + 1], &EXPECTED);
}

#[test]
fn decode_multiple() {
	let mut buf = [0u8; 257];
	let first = build(&mut buf[1..]);
	let second = build(&mut buf[1 + first..]);
	let received = 1 + first + second;

	let msg = nlmsghdr::<Nf>::ref_from_bytes(&buf[1..received]).unwrap();
	assert_eq!(msg.frame_length(), first);

	for offset in [1, 1 + first] {
		let msg = nlmsghdr::<Nf>::ref_from_bytes(&buf[offset..received]).unwrap();
		let Body::Msg(hdr, attrs) = msg.body() else {
			panic!("expected a message")
		};
		assert_eq!(hdr.family, 2);
		let attrs: std::vec::Vec<_> = attrs.collect();
		assert_eq!(attrs.len(), 2);
		let orig = attrs[0];
		assert!(orig.is_nested());
		assert_eq!(orig.typ(), 1);
		let mut nested = orig.nested();
		let src = nested.next().unwrap().nested().next().unwrap();
		assert_eq!((src.typ(), &src.value), (1, &[192u8, 168, 0, 1][..]));
		let num = nested.next().unwrap().nested().next().unwrap();
		assert_eq!(&num.value, &[17]);
		assert!(nested.next().is_none());
		assert_eq!(&attrs[1].value, b"abc");
	}
}

#[test]
fn truncated_attr_stops() {
	let mut buf = [0u8; 256];
	let len = build(&mut buf);
	let msg = nlmsghdr::<Nf>::ref_from_bytes(&buf[..len - 4]).unwrap();
	let Body::Msg(_, attrs) = msg.body() else {
		panic!()
	};
	assert_eq!(attrs.count(), 1);
}

/// Write a control message with an i32/nlmsgerr payload, optionally echoing a request and appending an ext-ack message
fn control(buf: &mut [u8], typ: u16, err: &nlmsgerr, capped: bool, echo: &[u8], tlv: Option<&str>) {
	let msg = nlmsghdr::<Raw>::mut_from_bytes(buf).unwrap();
	msg.clear();
	msg.typ.set(typ);
	let mut flags = if capped { NLM_F_CAPPED } else { 0 };
	if typ == NLMSG_ERROR {
		msg.put_header(err);
	} else {
		msg.put_header(&err.error);
	}
	if !echo.is_empty() {
		msg.put_header(echo);
	}
	if let Some(text) = tlv {
		flags |= NLM_F_ACK_TLVS;
		let mut a = msg.append();
		a.put_typ(NLMSGERR_ATTR_MSG).put_slice(text.as_bytes());
		a.put_u8(0);
	}
	msg.flags.set(flags);
}
fn err(code: i32, echo_len: u32) -> nlmsgerr {
	nlmsgerr {
		error: code.into(),
		msg_len: (16 + echo_len).into(),
		msg_typ: 0x0101.into(),
		msg_flags: 0.into(),
		msg_seq: 7.into(),
		msg_pid: 0.into(),
	}
}

#[test]
fn ack() {
	let mut buf = [0u8; 64];
	control(&mut buf, NLMSG_ERROR, &err(0, 0), true, &[], None);
	let msg = nlmsghdr::<Nf>::ref_from_bytes(&buf).unwrap();
	assert!(matches!(msg.body(), Body::Ack(a) if a.clone().count() == 0));
}

#[test]
fn error_uncapped_with_ext_ack() {
	let mut buf = [0u8; 128];
	// Echoed request payload contains bytes that would parse as an attribute; they must be skipped
	let echo = [8, 0, NLMSGERR_ATTR_MSG as u8, 0, b'n', b'o', 0, 0];
	control(
		&mut buf,
		NLMSG_ERROR,
		&err(-2, 8),
		false,
		&echo,
		Some("Bad thing"),
	);
	let msg = nlmsghdr::<Nf>::ref_from_bytes(&buf).unwrap();
	let Body::Error(e) = msg.body() else { panic!() };
	assert_eq!(e.code, -2);
	assert_eq!(e.request.unwrap().msg_seq.get(), 7);
	assert_eq!(e.message(), Some("Bad thing"));
}

#[test]
fn error_capped_with_ext_ack() {
	let mut buf = [0u8; 128];
	control(&mut buf, NLMSG_ERROR, &err(-22, 8), true, &[], Some("Nope"));
	let msg = nlmsghdr::<Nf>::ref_from_bytes(&buf).unwrap();
	let Body::Error(e) = msg.body() else { panic!() };
	assert_eq!((e.code, e.message()), (-22, Some("Nope")));
}

#[test]
fn done() {
	let mut buf = [0u8; 64];
	control(&mut buf, NLMSG_DONE, &err(0, 0), false, &[], None);
	let msg = nlmsghdr::<Nf>::ref_from_bytes(&buf).unwrap();
	assert!(matches!(msg.body(), Body::Done(_)));

	control(&mut buf, NLMSG_DONE, &err(-16, 0), false, &[], Some("Busy"));
	let msg = nlmsghdr::<Nf>::ref_from_bytes(&buf).unwrap();
	let Body::Error(e) = msg.body() else { panic!() };
	assert!(e.request.is_none());
	assert_eq!((e.code, e.message()), (-16, Some("Busy")));
}

#[test]
fn unknown() {
	let mut buf = [0u8; 64];
	control(&mut buf, NLMSG_NOOP, &err(0, 0), false, &[], None);
	let msg = nlmsghdr::<Nf>::ref_from_bytes(&buf).unwrap();
	assert!(matches!(msg.body(), Body::Unknown));
	// Truncated family header
	let msg = nlmsghdr::<Nf>::mut_from_bytes(&mut buf[..]).unwrap();
	msg.clear();
	msg.typ.set(0x0101);
	msg.put_header(&[1u8, 2]);
	let len = 18; // unpadded
	let msg = nlmsghdr::<Nf>::mut_from_bytes(&mut buf[..len]).unwrap();
	msg.len.set(len as u32);
	assert!(matches!(msg.body(), Body::Unknown));
}

#[test]
#[should_panic(expected = "advance out of bounds")]
fn overflow_panics() {
	let mut buf = [0u8; 24];
	let msg = nlmsghdr::<Raw>::mut_from_bytes(&mut buf).unwrap();
	msg.clear();
	msg.append().put_slice(&[0; 8]);
}

#[cfg(feature = "socket")]
mod route {
	use super::*;
	use zerocopy::native_endian::{I32, U16, U32};

	#[repr(C)]
	#[derive(KnownLayout, Immutable, Unaligned, FromBytes, IntoBytes)]
	pub struct ifinfomsg {
		pub family: u8,
		pad: u8,
		pub typ: U16,
		pub index: I32,
		pub flags: U32,
		pub change: U32,
	}
	pub struct Route;
	pub enum Rt<'a> {
		Link(&'a ifinfomsg),
	}
	impl Protocol for Route {
		type Header<'a> = Rt<'a>;
		fn header<'a>(typ: u16, p: &'a [u8]) -> Option<(Rt<'a>, usize)> {
			match typ {
				16..=19 => view(p).map(|(h, n)| (Rt::Link(h), n)),
				_ => None,
			}
		}
	}
	const RTM_GETLINK: u16 = 18;
	const IFLA_IFNAME: u16 = 3;

	fn request(buf: &mut [u8], flags: u16, index: i32) -> &mut nlmsghdr<Route> {
		let msg = nlmsghdr::<Route>::mut_from_bytes(buf).unwrap();
		msg.clear();
		msg.typ.set(RTM_GETLINK);
		msg.flags.set(NLM_F_REQUEST | flags);
		msg.put_header(&ifinfomsg {
			family: 0,
			pad: 0,
			typ: 0.into(),
			index: index.into(),
			flags: 0.into(),
			change: 0.into(),
		});
		msg
	}

	/// Dump links and look for loopback
	#[test]
	fn dump_links() {
		let mut sock = Netlink::new(NETLINK_ROUTE).unwrap();
		let mut buf = std::vec![0u8; 32768];
		let seq = sock.send(request(&mut buf, NLM_F_DUMP, 0)).unwrap();

		let mut found_lo = false;
		'recv: loop {
			let received = sock.recv(&mut buf).unwrap();
			assert!(received <= buf.len(), "truncated");
			let mut offset = 0;
			while offset < received {
				let msg = nlmsghdr::<Route>::ref_from_bytes(&buf[offset..received]).unwrap();
				assert_eq!(msg.seq.get(), seq);
				match msg.body() {
					Body::Msg(Rt::Link(link), attrs) => {
						assert!(link.index.get() > 0);
						found_lo |= attrs
							.filter(|a| a.typ() == IFLA_IFNAME)
							.any(|a| a.value == *b"lo\0");
					}
					Body::Done(_) => break 'recv,
					Body::Error(e) => panic!("{e:?}"),
					_ => panic!("unexpected message {msg:?}"),
				}
				offset += msg.frame_length();
			}
		}
		assert!(found_lo);
	}

	/// Ask for a link that doesn't exist: expect an uncapped error quoting our request
	#[test]
	fn missing_link_errors() {
		let mut sock = Netlink::new(NETLINK_ROUTE).unwrap();
		let mut buf = std::vec![0u8; 4096];
		let seq = sock.send(request(&mut buf, NLM_F_ACK, i32::MAX)).unwrap();
		let received = sock.recv(&mut buf).unwrap();
		let msg = nlmsghdr::<Route>::ref_from_bytes(&buf[..received]).unwrap();
		let Body::Error(e) = msg.body() else {
			panic!("expected error, got {msg:?}")
		};
		assert_eq!(e.code, -libc::ENODEV);
		assert_eq!(e.request.unwrap().msg_seq.get(), seq);
		std::println!("{e:?}");
		let io: std::io::Error = e.into();
		assert_eq!(io.raw_os_error(), Some(libc::ENODEV));
	}
}
