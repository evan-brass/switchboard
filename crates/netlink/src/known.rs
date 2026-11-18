//! Constants common to every netlink protocol (from `linux/netlink.h`).
//! Protocol specific values (message types, attribute types, family headers) belong in wrapper crates.

// Protocol families (the `proto` argument to socket(AF_NETLINK, ..))
pub const NETLINK_ROUTE: i32 = 0;
pub const NETLINK_SOCK_DIAG: i32 = 4;
pub const NETLINK_NETFILTER: i32 = 12;
pub const NETLINK_GENERIC: i32 = 16;

// Control message types (nlmsghdr.typ)
pub const NLMSG_NOOP: u16 = 0x1;
pub const NLMSG_ERROR: u16 = 0x2;
pub const NLMSG_DONE: u16 = 0x3;
pub const NLMSG_OVERRUN: u16 = 0x4;
/// Message types below this are reserved for control messages
pub const NLMSG_MIN_TYPE: u16 = 0x10;

// Standard flags (nlmsghdr.flags)
pub const NLM_F_REQUEST: u16 = 0x01;
pub const NLM_F_MULTI: u16 = 0x02;
pub const NLM_F_ACK: u16 = 0x04;
pub const NLM_F_ECHO: u16 = 0x08;
pub const NLM_F_DUMP_INTR: u16 = 0x10;
pub const NLM_F_DUMP_FILTERED: u16 = 0x20;

// Modifiers to GET requests
pub const NLM_F_ROOT: u16 = 0x100;
pub const NLM_F_MATCH: u16 = 0x200;
pub const NLM_F_ATOMIC: u16 = 0x400;
pub const NLM_F_DUMP: u16 = NLM_F_ROOT | NLM_F_MATCH;

// Modifiers to NEW requests
pub const NLM_F_REPLACE: u16 = 0x100;
pub const NLM_F_EXCL: u16 = 0x200;
pub const NLM_F_CREATE: u16 = 0x400;
pub const NLM_F_APPEND: u16 = 0x800;

// Modifiers to DELETE requests
pub const NLM_F_NONREC: u16 = 0x100;
pub const NLM_F_BULK: u16 = 0x200;

// Flags for ACK (NLMSG_ERROR) messages
pub const NLM_F_CAPPED: u16 = 0x100;
pub const NLM_F_ACK_TLVS: u16 = 0x200;

// Extended ack attributes (follow nlmsgerr when NLM_F_ACK_TLVS is set)
pub const NLMSGERR_ATTR_MSG: u16 = 1;
pub const NLMSGERR_ATTR_OFFS: u16 = 2;
pub const NLMSGERR_ATTR_COOKIE: u16 = 3;
pub const NLMSGERR_ATTR_POLICY: u16 = 4;
pub const NLMSGERR_ATTR_MISS_TYPE: u16 = 5;
pub const NLMSGERR_ATTR_MISS_NEST: u16 = 6;

// Attribute type flags (nlattr typ)
pub const NLA_F_NESTED: u16 = 0x8000;
pub const NLA_F_NET_BYTEORDER: u16 = 0x4000;
pub const NLA_TYPE_MASK: u16 = !(NLA_F_NESTED | NLA_F_NET_BYTEORDER);

// Socket options (level SOL_NETLINK)
pub const SOL_NETLINK: i32 = 270;
pub const NETLINK_ADD_MEMBERSHIP: i32 = 1;
pub const NETLINK_DROP_MEMBERSHIP: i32 = 2;
pub const NETLINK_CAP_ACK: i32 = 10;
pub const NETLINK_EXT_ACK: i32 = 11;
pub const NETLINK_GET_STRICT_CHK: i32 = 12;
