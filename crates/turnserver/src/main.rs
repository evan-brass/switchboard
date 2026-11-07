use std::{
	io::{ErrorKind, IoSlice, IoSliceMut, Write},
	net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
	os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd},
	process::{Command, Stdio},
	ptr::null_mut,
	str::FromStr,
};

use eyre::{OptionExt, Result, eyre};
use ipnet::{Ipv4Net, Ipv6Net};
use mio::{Events, Interest, Poll, Token, unix::SourceFd};
use nix::{
	cmsg_space,
	errno::Errno,
	libc::{in_pktinfo, in6_pktinfo},
	sys::socket::{
		ControlMessage, ControlMessageOwned, MsgFlags, RecvMsg, SetSockOpt, SockaddrStorage,
		getpeername, recvmsg, sendmsg,
		sockopt::{Ipv4PacketInfo, Ipv6RecvPacketInfo},
	},
};
use socket2::{Domain, Protocol, Socket, Type};
use stun::{
	Class, Request, RequestedTransport, Stun,
	errcode::{ClientErr, ErrCode},
	known,
	zerocopy::TryFromBytes,
};
use tracing::{error, info, warn};
use tracing_subscriber::{EnvFilter, util::SubscriberInitExt};

fn main() -> Result<()> {
	let ts = tracing_subscriber::fmt::Subscriber::builder()
		.with_env_filter(EnvFilter::from_default_env());
	SubscriberInitExt::try_init(ts)?;

	// Figure out what subnet we're supposed to assign to our vpn interface
	let net = match std::env::var("NET") {
		Err(std::env::VarError::NotPresent) => "2001:db8::3478:0:0/96".into(),
		v => v?,
	};
	let net = Ipv6Net::from_str(&net)?;
	if net.prefix_len() != 96 {
		return Err(eyre!("Your network must be a /96"));
	}
	let router = net
		.hosts()
		.nth(1)
		.ok_or_eyre("The behavior of ipnet's Ipv6AddrRange must have changed.")?;

	// Apply our firewall rules using a child nft process
	let mut nft = Command::new("/usr/sbin/nft")
		.args(["-i"])
		.stdin(Stdio::piped())
		.stderr(Stdio::inherit())
		.stdout(Stdio::inherit())
		.spawn()?;
	let mut rules = nft.stdin.take().ok_or_eyre("Where's the nft stdin?")?;
	// TODO: Might want to move this later in the program so that we don't trample anything else running on :3478 before we bind the socket...
	rules.write_all(include_bytes!("../rules.nft"))?;

	// Enable ipv6 forwarding
	std::fs::write("/proc/sys/net/ipv6/conf/all/forwarding", "1")?;

	// Setup async
	let mut events = Events::with_capacity(256);
	let mut poll = Poll::new()?;

	// Create our vpn interface
	let tun = tun_rs::DeviceBuilder::new()
		.ipv6(router, net.netmask())
		.enable(false)
		.build_sync()?;

	// 0.0.0.0:8743/udp, 0.0.0.0:3478/udp, [::]:3478/udp?v6-only, [::]:3478/tcp
	let sock_stateless = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
	let sock_nat4 = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
	let sock_nat6 = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
	let sock_stream = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;

	// For tcp streams we map their fd into 0.0.0.0/8
	let fd_net = Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 8).unwrap();
	// We need to mask out all our currently open file descriptors so that they aren't publicly reachable/writable...
	// This isn't doing that, it is just guessing that we've used all the fds from 0-sock_stream.
	let fd_net_bottom = [&sock_stateless, &sock_nat4, &sock_nat6, &sock_stream]
		.map(|s| s.as_raw_fd() as u32 + 1)
		.into_iter()
		.max()
		.unwrap();
	let fd_net_hosts = fd_net_bottom..=fd_net.hostmask().to_bits();

	sock_nat6.set_only_v6(true)?;
	sock_stream.set_only_v6(false)?;

	Ipv4PacketInfo.set(&sock_stateless, &true)?;
	Ipv4PacketInfo.set(&sock_nat4, &true)?;
	Ipv6RecvPacketInfo.set(&sock_nat6, &true)?;

	sock_stateless.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 8743).into())?;
	sock_nat4.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 3478).into())?;
	sock_nat6.bind(&SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 3478, 0, 0).into())?;
	sock_stream.bind(&SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 3478, 0, 0).into())?;

	tun.set_nonblocking(true)?;
	sock_stateless.set_nonblocking(true)?;
	sock_nat4.set_nonblocking(true)?;
	sock_nat6.set_nonblocking(true)?;
	sock_stream.set_nonblocking(true)?;

	sock_stream.listen(10)?;

	fn register(poll: &Poll, fd: RawFd) -> Result<()> {
		let token = Token(fd as usize);
		poll.registry()
			.register(&mut SourceFd(&fd), token, Interest::READABLE)?;
		Ok(())
	}
	register(&poll, tun.as_raw_fd())?;
	let tun_token = Token(tun.as_raw_fd() as usize);
	register(&poll, sock_stateless.as_raw_fd())?;
	register(&poll, sock_nat4.as_raw_fd())?;
	register(&poll, sock_nat6.as_raw_fd())?;
	register(&poll, sock_stream.as_raw_fd())?;
	let accept_token = Token(sock_stream.as_raw_fd() as usize);

	let mut buffer = vec![0; 65536].into_boxed_slice();

	loop {
		let mut do_accept = false;
		'event: for e in events.into_iter() {
			if e.token() == tun_token {
				todo!("{e:?}")
			}
			if e.token() == accept_token {
				do_accept = true;
				continue;
			}
			let fd = e.token().0 as RawFd;
			let is_tcp = fd_net_hosts.contains(&(fd as u32));

			let mut do_dispose = e.is_error() || e.is_read_closed() || e.is_write_closed();
			loop {
				// SAFETY: Always perform at least one syscall to check for closed sockets (EBADF) before double closing in do_dispose
				let mut iov = [IoSliceMut::new(&mut buffer)];
				// Responses have to come from the same IP that the request was sent to
				let mut control = cmsg_space!(in6_pktinfo, in_pktinfo);
				let received_msg = match recvmsg::<SockaddrStorage>(
					fd,
					&mut iov,
					Some(&mut control),
					if is_tcp {
						MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_PEEK
					} else {
						MsgFlags::MSG_DONTWAIT
					},
				) {
					// SAFETY: Detect already closed sockets
					Err(Errno::EBADF) => continue 'event,
					Err(Errno::EWOULDBLOCK) => break,
					Err(_) => {
						if is_tcp {
							do_dispose = true;
						}
						break;
					}
					// If there's less than 20 bytes read don't even try to read it as STUN
					// Otherwise, bad data in the buffer from a previous read could close unrelated tcp streams.
					// This isn't a problem for UDP since those are always complete/error
					// TODO: I don't really know in what situation address would be None...
					Ok(RecvMsg { bytes: ..20, .. }) | Ok(RecvMsg { address: None, .. }) => {
						// Partially received TCP -> wait, UDP -> skip/drop
						if is_tcp && !do_dispose {
							continue;
						} else {
							break;
						}
					}
					Ok(v) => v,
				};
				let RecvMsg {
					bytes: available,
					address,
					flags: _, // TODO: Do I need this?
					..
				} = received_msg;

				// For UDP clients, send the response via the same local IP they used to contact us
				// I'm not exactly sure how nix fucked this API up so bad. It's borderline "just call the syscalls manually" bad.
				// The linux CMSG crap breeds bullshit I suppose.
				// control_out isn't even the real CMSG buffer, it's a temporary list that nix's sendmsg assembles into its own internal Vec.
				let pi4;
				let pi6;
				let mut control_out = Vec::with_capacity(1);
				for cmsg in received_msg.cmsgs()? {
					match cmsg {
						ControlMessageOwned::Ipv4PacketInfo(pi) => {
							pi4 = pi;
							control_out.push(ControlMessage::Ipv4PacketInfo(&pi4));
							break;
						}
						ControlMessageOwned::Ipv6PacketInfo(pi) => {
							pi6 = pi;
							control_out.push(ControlMessage::Ipv6PacketInfo(&pi6));
							break;
						}
						_ => warn!("Unused control message {cmsg:?}"),
					}
				}

				// Reconstitute the peer address
				let address = address.unwrap();
				let sender = if is_tcp {
					getpeername::<SockaddrStorage>(fd)
						.ok()
						.as_ref()
						.and_then(SockaddrStorage::as_sockaddr_in6)
						.cloned()
						.map(Into::into)
						.map(SocketAddr::V6)
				} else {
					Option::xor(
						address
							.as_sockaddr_in()
							.cloned()
							.map(Into::into)
							.map(SocketAddr::V4),
						address
							.as_sockaddr_in6()
							.cloned()
							.map(Into::into)
							.map(SocketAddr::V6),
					)
				};

				let buffer_length = buffer.len();
				let msg = match Stun::try_mut_from_bytes(&mut buffer) {
					Err(stun::zerocopy::ConvertError::Validity(v)) => {
						info!("Stun message invalid {v} closing");
						do_dispose = true;
						break;
					}
					Err(e) => panic!("{e:?}"),
					Ok(v) => v,
				};

				let frame_length = msg.frame_length();
				// Frames which exceed our buffer
				if frame_length > buffer_length {
					do_dispose = true;
					break;
				}
				// Frames which are not fully received
				if frame_length > available {
					// Partially received TCP -> wait, UDP -> skip/drop
					if is_tcp { break } else { continue }
				}
				// Consume the frame
				if is_tcp {
					let mut remaining = frame_length;
					while remaining > 0 {
						let ret = unsafe {
							nix::libc::recv(fd, null_mut(), remaining, MsgFlags::MSG_TRUNC.bits())
						};
						remaining =
							remaining.saturating_sub(Errno::result(ret).map(|r| r as usize)?);
					}
				}

				info!("STUN: {fd} {:?} {:?} {sender:?}", msg.typ, msg.id);
				let Class::Req(method) = msg.typ else {
					info!("Dropping non-request message");
					continue;
				};

				let Some(sender) = sender else {
					warn!("Failed to reconstitute sender for {fd} {address}");
					continue;
				};

				let mut error: Option<(ErrCode, &str)> = None;
				let mut unknown_attributes = Vec::new();

				for (_, attr) in msg.into_iter() {
					match attr.typ {
						known::REQUESTED_TRANSPORT => {
							let Ok(_) = RequestedTransport::try_read_from_bytes(&attr.value) else {
								error = Some((ClientErr::UnsupportedTransportProtocol.into(), ""));
								break;
							};
						}
						_ if attr.is_comprehension_required() => {
							unknown_attributes.push(attr.typ);
							warn!(" - {:04X} {:?}", u16::from_be(attr.typ), &attr.value);
						}
						_ => {
							info!(" - {:04X} {:?}", u16::from_be(attr.typ), &attr.value);
						}
					}
				}
				// TODO: return 401/403/441 if attributes are missing
				match method {
					Request::Bind => {
						msg.clear();
						msg.typ = method.success().into();
						msg.append()
							.put_typ(known::XOR_MAPPED_ADDRESS)
							.put_xor_address(sender);
					}
					_ => continue,
				}

				// Unknown Attributes supercede any other errors I guess
				if !unknown_attributes.is_empty() {
					error = Some((ClientErr::UnknownAttribute.into(), ""));
				}

				// Report errors
				if let Some((code, reason)) = error {
					info!("Message handling returned error {code:?} {reason}");
					if method.is_indication() {
						continue;
					}
					msg.clear();
					msg.typ = method.failure().into();
					std::fmt::write(
						msg.append().put_typ(known::ERROR_CODE).put_errorcode(code),
						format_args!("{reason}"),
					)?;
					// TODO: Append an UnknownAttributes list?
				}

				// Send the response
				let frame_length = msg.frame_length();
				// TODO: For TCP clients, verify that we wouldn't overfill (past 1/2) socket's send buffer
				let mut start = 0;

				while start < frame_length {
					let iov = &[IoSlice::new(&buffer[start..frame_length])];
					let written =
						match sendmsg(fd, iov, &control_out, MsgFlags::empty(), Some(&address)) {
							Err(Errno::EINTR | Errno::EAGAIN) => continue,
							Err(e) => {
								info!("sndmsg error {e}");
								do_dispose = true;
								break;
							}
							Ok(n) => n,
						};
					start += written;
				}
			}

			if is_tcp && do_dispose {
				// SAFETY: We've checked that the socket is alive (not EBADF) so we just close/Drop.  If this is a problem, then just call close manually and check for errors.
				info!("Closing stream");
				poll.registry().deregister(&mut SourceFd(&fd))?;
				unsafe { OwnedFd::from_raw_fd(fd) };
			}
		}
		if do_accept {
			loop {
				let (stream, address) = match sock_stream.accept() {
					Err(e) if e.kind() == ErrorKind::Interrupted => continue,
					Err(e) if e.kind() == ErrorKind::WouldBlock => break,
					Err(e) if e.kind() == ErrorKind::ConnectionAborted => continue,
					Err(e) => {
						warn!("{e} during tcp accept");
						break;
					}
					Ok(v) => v,
				};
				let fd = stream.as_raw_fd();
				if !fd_net_hosts.contains(&(fd as u32)) {
					error!(
						"{fd} is not within our fd network! Dropping connection from {address:?}"
					);
					continue;
				}
				if let Err(e) = register(&poll, fd) {
					error!("{e} during stream poll registration.");
					continue;
				};
				// Leak the fd now that we've registered it
				let _ = stream.into_raw_fd();
			}
		}
		match poll.poll(&mut events, None) {
			Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => {
				continue;
			}
			v => v?,
		}
	}
}
