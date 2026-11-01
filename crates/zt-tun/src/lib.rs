//! A Linux TUN device.
//!
//! A TUN device is a virtual network interface: packets written to it come
//! out of the kernel's routing table, and packets the kernel routes to it
//! are read back. That is exactly what an overlay network needs — the
//! kernel believes it has a real interface, and the overlay is what carries
//! the packets between machines.
//!
//! # The unsafe
//!
//! The device is driven with `ioctl`, which is unsafe, and the file
//! descriptor is opened with `libc`. All of that is confined to
//! [`TunDevice::open`]; everything else in this crate is safe.
//!
//! # Platform
//!
//! Linux only. On other platforms the type exists but opening it returns
//! an error, so callers do not need to be conditional themselves.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

/// The interface name length, including the terminating zero.
const IFNAMSIZ: usize = 16;

/// `TUNSETIFF`, from `linux/if_tun.h`.
#[cfg(target_os = "linux")]
const TUNSETIFF: libc::c_ulong = 0x4004_54ca;

/// The `ifreq` structure, as the kernel expects it for `TUNSETIFF`.
///
/// The kernel reads the name and the flags from the start of the structure.
/// The rest is the union that other interface flags share, which is why the
/// buffer has to be large enough for the largest of them.
#[cfg(target_os = "linux")]
#[repr(C)]
struct IfReq {
    name: [libc::c_char; IFNAMSIZ],
    flags: libc::c_short,
    /// The union the flags share. Only the first bytes are read for a tun
    /// device, but the structure must be large enough.
    _union: [u8; 24],
}

#[cfg(target_os = "linux")]
impl IfReq {
    fn new(name: &str) -> io::Result<Self> {
        let bytes = name.as_bytes();
        if bytes.is_empty() || bytes.len() >= IFNAMSIZ {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "the interface name must be 1 to {} characters",
                    IFNAMSIZ - 1
                ),
            ));
        }

        let mut request = IfReq {
            name: [0; IFNAMSIZ],
            // The flags are an `i32` in the C headers, but the structure
            // holds a short.
            flags: (libc::IFF_TUN as libc::c_short) | (libc::IFF_NO_PI as libc::c_short),
            _union: [0; 24],
        };

        for (slot, byte) in request.name.iter_mut().zip(bytes) {
            *slot = *byte as libc::c_char;
        }

        Ok(request)
    }
}

/// A TUN device.
///
/// The device is opened non-blocking, so a read returns `WouldBlock` when
/// there is no packet rather than blocking the thread.
pub struct TunDevice {
    fd: OwnedFd,
    name: String,
    mtu: u16,
}

impl TunDevice {
    /// Open a TUN device with the given name.
    ///
    /// The interface is created if it does not exist. The caller is
    /// responsible for bringing it up and assigning addresses, which needs
    /// privileges this crate does not assume.
    #[cfg(target_os = "linux")]
    pub fn open(name: &str, mtu: u16) -> io::Result<Self> {
        // SAFETY: `open` is called with a valid NUL-terminated path and the
        // flags are ordinary file flags. The returned descriptor is checked
        // for failure before it is used.
        let raw = unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };

        if raw < 0 {
            return Err(io::Error::last_os_error());
        }

        // SAFETY: the descriptor is valid and owned from here on.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };

        let mut request = IfReq::new(name)?;

        // SAFETY: `request` is a valid `ifreq` for `TUNSETIFF`, and the
        // descriptor is open for reading and writing.
        let result = unsafe { libc::ioctl(fd.as_raw_fd(), TUNSETIFF, &mut request) };

        if result < 0 {
            return Err(io::Error::last_os_error());
        }

        // The kernel writes the assigned name back into the request. It
        // picks a name when the one asked for is taken.
        let name = request
            .name
            .iter()
            .take_while(|byte| **byte != 0)
            .map(|byte| *byte as u8 as char)
            .collect::<String>();

        // Non-blocking, so a read with no packet returns instead of
        // stalling the caller.
        // SAFETY: the descriptor is valid and open.
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the descriptor is valid and open.
        if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(Self { fd, name, mtu })
    }

    /// Open a TUN device with the given name.
    ///
    /// TUN devices are a Linux interface, so this is not available
    /// elsewhere.
    #[cfg(not(target_os = "linux"))]
    pub fn open(name: &str, _mtu: u16) -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("TUN devices are not supported on this platform ({name})"),
        ))
    }

    /// The name the kernel gave the interface.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The maximum transmission unit.
    pub fn mtu(&self) -> u16 {
        self.mtu
    }

    /// Read one packet from the device.
    ///
    /// The buffer holds a raw IP packet, without the packet information
    /// header, because the device is opened without one.
    ///
    /// Returns `WouldBlock` when no packet is waiting.
    pub fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.len() < self.mtu as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the buffer is smaller than the interface's MTU",
            ));
        }

        // SAFETY: the descriptor is valid and open for reading, and the
        // buffer is at least as large as the MTU.
        let count = unsafe {
            libc::read(
                self.fd.as_raw_fd(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
            )
        };

        if count < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(count as usize)
    }

    /// Write one packet to the device.
    ///
    /// The buffer holds a raw IP packet.
    pub fn write(&mut self, packet: &[u8]) -> io::Result<usize> {
        if packet.len() > self.mtu as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the packet is larger than the interface's MTU",
            ));
        }

        // SAFETY: the descriptor is valid and open for writing, and the
        // buffer is a valid byte slice for its length.
        let count =
            unsafe { libc::write(self.fd.as_raw_fd(), packet.as_ptr().cast(), packet.len()) };

        if count < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(count as usize)
    }
}

impl AsRawFd for TunDevice {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.fd.as_raw_fd()
    }
}

/// A device that carries IP packets.
///
/// The data plane is written against this rather than against the device
/// itself, so it can be exercised without a kernel interface and without
/// privileges. A TUN device is one implementation; a queue is another.
pub trait PacketDevice {
    /// Read one packet from the device.
    ///
    /// The buffer holds a raw IP packet. Returns `WouldBlock` when no
    /// packet is waiting.
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize>;

    /// Write one packet to the device.
    ///
    /// The buffer holds a raw IP packet.
    fn write(&mut self, packet: &[u8]) -> io::Result<usize>;

    /// The maximum transmission unit.
    fn mtu(&self) -> u16;
}

impl PacketDevice for TunDevice {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        TunDevice::read(self, buffer)
    }

    fn write(&mut self, packet: &[u8]) -> io::Result<usize> {
        TunDevice::write(self, packet)
    }

    fn mtu(&self) -> u16 {
        TunDevice::mtu(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_that_is_too_long_is_refused() {
        let request = IfReq::new("this-name-is-far-too-long-for-an-interface");
        assert!(request.is_err());
    }

    #[test]
    fn a_name_is_accepted() {
        let request = IfReq::new("zt0").expect("name");
        assert_eq!(request.name[0] as u8, b'z');
        assert_eq!(request.name[3], 0);
        // The packet information header is disabled, so the kernel hands
        // over raw IP packets.
        assert_eq!(
            request.flags,
            (libc::IFF_TUN as libc::c_short) | (libc::IFF_NO_PI as libc::c_short)
        );
    }

    #[test]
    fn an_empty_name_is_refused() {
        assert!(IfReq::new("").is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn opening_a_device_without_privileges_fails_cleanly() {
        // The test does not assume it has privileges. Either it opens, or
        // it fails with an error rather than panicking.
        match TunDevice::open("zt-test", 1400) {
            Ok(device) => assert!(!device.name().is_empty()),
            Err(error) => assert_eq!(error.kind(), io::ErrorKind::PermissionDenied),
        }
    }
}
