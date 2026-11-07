# Creating the TUN interface and modifying the firewall rules require NET_ADMIN
set -ex
cargo b
sudo systemd-run --pty --same-dir --uid="evan" -p AmbientCapabilities=CAP_NET_ADMIN -E RUST_LOG=trace "target/debug/turnserver"
