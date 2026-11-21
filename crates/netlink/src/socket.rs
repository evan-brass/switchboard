use crate::{Error, Protocol, known, nlmsghdr};
use std::{
	io,
	os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd},
};
use zerocopy::IntoBytes;

/// A blocking AF_NETLINK socket talking to the kernel (portid 0).
/// Created with NETLINK_EXT_ACK (error messages) and NETLINK_GET_STRICT_CHK (strict request validation) enabled.
/// Use the fd (AsFd) to set O_NONBLOCK, socket options (see `known::SOL_NETLINK`), or register with a poller.
pub struct Netlink {
	fd: OwnedFd,
	seq: u32,
}
impl Netlink {
	/// `proto` is one of `known::NETLINK_*`
	pub fn new(proto: i32) -> io::Result<Self> {
		let fd =
			unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, proto) };
		if fd < 0 {
			return Err(io::Error::last_os_error());
		}
		let sock = Self {
			fd: unsafe { OwnedFd::from_raw_fd(fd) },
			seq: 0,
		};
		sock.set_flag(known::NETLINK_EXT_ACK, true)?;
		sock.set_flag(known::NETLINK_GET_STRICT_CHK, true)?;
		Ok(sock)
	}

	/// Set a boolean SOL_NETLINK socket option (`known::NETLINK_*`)
	pub fn set_flag(&self, opt: i32, value: bool) -> io::Result<()> {
		let value = value as libc::c_int;
		let ret = unsafe {
			libc::setsockopt(
				self.fd.as_raw_fd(),
				known::SOL_NETLINK,
				opt,
				(&raw const value).cast(),
				size_of::<libc::c_int>() as libc::socklen_t,
			)
		};
		if ret < 0 {
			return Err(io::Error::last_os_error());
		}
		Ok(())
	}

	/// Stamps the message with the next sequence number and a pid of 0 (kernel assigned), then sends it.
	/// Returns the sequence number so the caller can match replies.
	pub fn send<P: Protocol>(&mut self, msg: &mut nlmsghdr<P>) -> io::Result<u32> {
		self.seq = self.seq.wrapping_add(1);
		msg.seq.set(self.seq);
		msg.pid.set(0);
		let len = msg.len() as usize;
		let Some(bytes) = msg.as_bytes().get(..len) else {
			panic!("Corruption: message length exceeds buffer");
		};
		loop {
			let ret = unsafe { libc::send(self.fd.as_raw_fd(), bytes.as_ptr().cast(), len, 0) };
			if ret >= 0 {
				return Ok(self.seq);
			}
			let err = io::Error::last_os_error();
			if err.kind() != io::ErrorKind::Interrupted {
				return Err(err);
			}
		}
	}

	/// Receive one datagram into `buf` (which may hold several messages).
	/// Returns the datagram's full length: if this exceeds the buffer, the datagram was truncated.
	pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
		loop {
			let ret = unsafe {
				libc::recv(
					self.fd.as_raw_fd(),
					buf.as_mut_ptr().cast(),
					buf.len(),
					libc::MSG_TRUNC,
				)
			};
			if ret >= 0 {
				return Ok(ret as usize);
			}
			let err = io::Error::last_os_error();
			if err.kind() != io::ErrorKind::Interrupted {
				return Err(err);
			}
		}
	}
}
impl AsFd for Netlink {
	fn as_fd(&self) -> BorrowedFd<'_> {
		self.fd.as_fd()
	}
}
impl AsRawFd for Netlink {
	fn as_raw_fd(&self) -> RawFd {
		self.fd.as_raw_fd()
	}
}
impl From<Netlink> for OwnedFd {
	fn from(value: Netlink) -> Self {
		value.fd
	}
}

impl From<Error<'_>> for io::Error {
	fn from(value: Error<'_>) -> Self {
		io::Error::from_raw_os_error(-value.code)
	}
}
