use std::{
	io::Write,
	net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6},
	os::fd::AsRawFd,
	process::{Command, Stdio},
	str::FromStr,
};

use eyre::{OptionExt, Result, eyre};
use ipnet::{Ipv4Net, Ipv6Net};
use mio::{Events, Interest, Poll, Token, unix::SourceFd};
use socket2::{Domain, Protocol, Socket, Type};

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
	let min_fd = sock_stream.as_raw_fd() as u32;

	sock_nat6.set_only_v6(true)?;
	sock_stream.set_only_v6(false)?;

	sock_stateless.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 8743).into())?;
	sock_nat4.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 3478).into())?;
	sock_nat6.bind(&SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 3478, 0, 0).into())?;
	sock_stream.bind(&SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 3478, 0, 0).into())?;

	// Setup async
	let events = Events::with_capacity(256);
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

	Ok(())
}
