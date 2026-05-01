use tun_tap::{Iface, Mode};

fn main() -> std::io::Result<()> {
    // Open /dev/net/tun and create a TUN interface named "tun0"
    // Mode::Tun = IP packets (no Ethernet header)
    // Mode::Tap = Ethernet frames (includes MAC headers) — we want Tun for this project
    let iface = Iface::new("tun0", Mode::Tun)?;

    println!("✓ TUN interface created: {}", iface.name());
    println!("  Now run in another terminal:");
    println!("  ip addr add 192.168.0.1/24 dev {}", iface.name());
    println!("  ip link set {} up", iface.name());
    println!("  ping 192.168.0.2   # our stack's address");

    // Read packets in a loop — just print their length for now
    let mut buf = [0u8; 1504];
    loop {
        let n = iface.recv(&mut buf)?;
        println!("Received {} bytes: {:02x?}", n, &buf[..n.min(20)]);
    }
}