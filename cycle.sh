# Creating the TUN interface and modifying the firewall rules require NET_ADMIN
set -ex
cargo b
sudo systemd-run --pty --same-dir --uid="$USER" -p AmbientCapabilities=CAP_NET_ADMIN -E RUST_BACKTRACE=full -E RUST_LOG=trace "strace" "target/debug/turnserver"
