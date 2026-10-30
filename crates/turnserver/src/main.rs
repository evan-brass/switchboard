use std::{
	io::{ErrorKind, IoSliceMut, Write},
	net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
	os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd},
	process::{Command, Stdio},
	str::FromStr,
};

use eyre::{OptionExt, Result, eyre};
use ipnet::{Ipv4Net, Ipv6Net};
use log::{error, warn};
use mio::{Events, Interest, Poll, Token, unix::SourceFd};
use nix::{
	errno::Errno,
	sys::socket::{MsgFlags, SockaddrStorage, recv, recvfrom},
};
use socket2::{Domain, Protocol, SockAddrStorage, Socket, Type};

const TUN: Token = Token(usize::MAX);
const STATELESS: Token = Token(usize::MAX - 1);
const NAT4: Token = Token(usize::MAX - 2);
const NAT6: Token = Token(usize::MAX - 3);
const STREAM: Token = Token(usize::MAX - 4);

fn main() -> Result<()> {
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

	// Create our vpn interface
	let tun = tun::create(&tun::configure().address(router).netmask(net.netmask()))?;

	// Apply our firewall rules using a child nft process
	let nft = Command::new("nft")
		.args(["-f", "-"])
		.stdin(Stdio::piped())
		.spawn()?;
	let mut rules = nft.stdin.ok_or_eyre("Where's the nft stdin?")?;
	rules.write_all(include_bytes!("../rules.nft"))?;

	// Enable ipv6 forwarding
	std::fs::write("/proc/sys/net/ipv6/conf/all/forwarding", "1")?;

	// 0.0.0.0:8743/udp, 0.0.0.0:3478/udp, [::]:3478/udp?v6-only, [::]:3478/tcp
	let sock_stateless = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
	let sock_nat4 = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
	let sock_nat6 = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
	let sock_stream = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;

	// For tcp streams we map their fd into 0.0.0.0/8
	let fd_net = Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 8).unwrap();
	// We need to mask out all our currently open file descriptors so that they aren't publicly reachable/writable...
	// This isn't doing that, it is just guessing that we've used all the fds from 0-sock_stream.
	let fd_net_hosts = (sock_stream.as_raw_fd() as u32 + 1)..=fd_net.hostmask().to_bits();

	sock_nat6.set_only_v6(true)?;
	sock_stream.set_only_v6(false)?;

	sock_stateless.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 8743).into())?;
	sock_nat4.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 3478).into())?;
	sock_nat6.bind(&SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 3478, 0, 0).into())?;
	sock_stream.bind(&SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 3478, 0, 0).into())?;

	// Setup async
	let mut events = Events::with_capacity(256);
	let mut poll = Poll::new()?;

	tun.set_nonblock()?;
	sock_stateless.set_nonblocking(true)?;
	sock_nat4.set_nonblocking(true)?;
	sock_nat6.set_nonblocking(true)?;
	sock_stream.set_nonblocking(true)?;

	poll.registry()
		.register(&mut SourceFd(&tun.as_raw_fd()), TUN, Interest::READABLE)?;
	poll.registry().register(
		&mut SourceFd(&sock_stateless.as_raw_fd()),
		STATELESS,
		Interest::READABLE,
	)?;
	poll.registry().register(
		&mut SourceFd(&sock_nat4.as_raw_fd()),
		NAT4,
		Interest::READABLE,
	)?;
	poll.registry().register(
		&mut SourceFd(&sock_nat6.as_raw_fd()),
		NAT6,
		Interest::READABLE,
	)?;
	poll.registry().register(
		&mut SourceFd(&sock_stream.as_raw_fd()),
		STREAM,
		Interest::READABLE,
	)?;

	let mut buffer = vec![0; 65536].into_boxed_slice();

	loop {
		let mut do_accept = false;
		'event: for e in events.into_iter() {
			match e.token() {
				// We delay accepting new clients until we've handled all existing ones.
				// This ensures we don't introduce new fds until the old ones are potentially
				// cleaned up.  That means receiving mutliple events for the same fd where
				// we've already closed it should be fine: we just recv on an empty fd instead
				// of possibly recv on a newly accepted fd.
				STREAM => do_accept = true,
				STATELESS | NAT4 | NAT6 => loop {
					let sock = match e.token() {
						STATELESS => &sock_stateless,
						NAT4 => &sock_nat4,
						NAT6 => &sock_nat6,
						_ => unreachable!(),
					};
					let (datalen, peer): (usize, SockaddrStorage) =
						match recvfrom(sock.as_raw_fd(), &mut buffer) {
							Err(Errno::EWOULDBLOCK) => break,
							Err(e) => {
								warn!("{e} on recvfrom for {:?}", sock.local_addr());
								break;
							}
							Ok((..20, _)) => continue,
							Ok((_, None)) => {
								warn!("recvfrom returned no client address?");
								continue;
							}
							Ok((n, Some(peer))) => (n, peer),
						};
					// TODO: Parse the message, emit the response
				},
				Token(i) => {
					let raw = i as RawFd;
					let mut do_dispose = e.is_error() || e.is_read_closed() || e.is_write_closed();
					loop {
						// SAFETY: Always perform at least one syscall to check for closed sockets (EBADF) before double closing in do_dispose
						let available = match recv(
							raw,
							&mut buffer,
							MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_PEEK,
						) {
							// SAFETY: Detect already closed sockets
							Err(Errno::EBADF) => continue 'event,
							Err(Errno::EWOULDBLOCK) => break,
							Err(_) => {
								do_dispose = true;
								break;
							}
							// If there's less than 20 bytes read don't even try to read it as STUN
							// Otherwise, bad data in the buffer from a previous read could unrelated tcp streams.
							// This isn't a problem for UDP since those are always complete/error
							Ok(..20) => break,
							Ok(n) => n,
						};
						// TODO: Parse the message, emit the response
						// TODO: Use a blocking read to consume
					}
					if do_dispose {
						// SAFETY: We've checked that the socket is alive (not EBADF) so we just close/Drop.  If this is a problem, then just call close manually and check for errors.
						unsafe { OwnedFd::from_raw_fd(raw) };
					}
				}
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
				let raw = stream.as_raw_fd();
				if !fd_net_hosts.contains(&(raw as u32)) {
					error!(
						"{raw} is not within our fd network! Dropping connection from {address:?}"
					);
					continue;
				}
				if let Err(e) = poll.registry().register(
					&mut SourceFd(&raw),
					Token(raw as usize),
					Interest::READABLE,
				) {
					error!("{e} during stream poll registration.");
					continue;
				};
				// Leak the fd now that we've registered it
				let _ = stream.into_raw_fd();
			}
		}
		poll.poll(&mut events, None)?;
	}
}
