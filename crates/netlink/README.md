# Netlink
Bare-bones, zero-copy encoding and decoding of netlink messages and attributes (`no_std`).
Protocol specific types (family headers, message / attribute types) are left to wrapper crates.
The `socket` feature adds a minimal `Netlink` socket wrapper.

Reading handles one message at a time: if `msg.frame_length()` is less than the bytes received, the
next message starts at that offset.
