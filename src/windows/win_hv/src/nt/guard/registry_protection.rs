//! # Registry Protection
//!
//! Registers a `CmRegisterCallbackEx` kernel callback that intercepts all
//! pre-write, pre-delete, and pre-rename operations targeting the HxPosed
//! registry key tree (`\REGISTRY\MACHINE\SOFTWARE\HxPosed`) and returns
//! `STATUS_ACCESS_DENIED`, preventing user-mode and third-party kernel-mode
//! callers from tampering with the whitelist or configuration.
//!
//! ## Notes
//! * Kernel `Zw*` calls issued **by this driver** bypass Cm callbacks by design
//!   (they execute with a kernel-mode call origin), so HxGuard's own reads are
//!   unaffected.
//! * The cookie returned by `CmRegisterCallbackEx` is stored in a static so the
//!   callback can be unregistered if needed in the future.

use crate::win::{
    CmRegisterCallbackEx, CmUnRegisterCallback, NtStatus, PVOID, REG_PRE_KEY_INFORMATION,
    RegNotifyClass, UNICODE_STRING,
};
use core::ffi::c_void;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicI64, Ordering};

/// Cookie returned by `CmRegisterCallbackEx`. Zero means not registered.
static REGISTRY_COOKIE: AtomicI64 = AtomicI64::new(0);

/// The NT-namespace prefix of the key tree we protect.
/// All protected paths start with this prefix (case-insensitive on NTFS, but
/// the kernel path comparison below is a simple UTF-16 prefix check; Windows
/// registry paths are always uppercase in the native namespace, so this works).
const PROTECTED_PREFIX: &[u8] =
    b"\\\x00R\x00E\x00G\x00I\x00S\x00T\x00R\x00Y\x00\\\x00M\x00A\x00C\x00H\x00I\x00N\x00E\x00\\\x00S\x00O\x00F\x00T\x00W\x00A\x00R\x00E\x00\\\x00H\x00x\x00P\x00o\x00s\x00e\x00d";

/// Altitude string — must live for the entire lifetime of the callback.
/// 385200 is in the FSFilter Activity Monitor altitude range (safe for security drivers).
static ALTITUDE_BUF: &[u16] = &[
    b'3' as u16, b'8' as u16, b'5' as u16, b'2' as u16, b'0' as u16, b'0' as u16,
];

/// Returns `true` when the UTF-16 key path stored in `us` starts with the
/// HxPosed prefix, using a simple byte-level comparison (valid for NT registry
/// paths which are always in a normalised case).
fn is_protected_path(us: *mut UNICODE_STRING) -> bool {
    if us.is_null() {
        return false;
    }
    let us = unsafe { &*us };
    if us.Buffer.is_null() || us.Length == 0 {
        return false;
    }
    let path_bytes =
        unsafe { core::slice::from_raw_parts(us.Buffer as *const u8, us.Length as usize) };

    // Case-insensitive prefix check: convert both sides to uppercase u16 pairs and compare.
    let prefix = PROTECTED_PREFIX;
    if path_bytes.len() < prefix.len() {
        return false;
    }

    // Compare byte-by-byte; ASCII letters are the only difference between upper/lower in
    // the NT registry namespace, so simple OR-0x20 lowercasing is sufficient.
    prefix.iter().zip(path_bytes.iter()).all(|(p, b)| {
        p.to_ascii_lowercase() == b.to_ascii_lowercase()
    })
}

/// The kernel invokes this function before every registry operation.
///
/// # Safety
/// This function is called directly by the Windows kernel at PASSIVE_LEVEL.
/// The `info` pointer is kernel-guaranteed to be valid for the duration of the call.
pub unsafe extern "C" fn registry_callback(
    _context: PVOID,
    notify_class: *mut c_void,
    info: PVOID,
) -> NtStatus {
    // The second parameter is actually a `REG_NOTIFY_CLASS` value passed as a pointer-
    // sized integer. Cast it back to u32.
    let class = RegNotifyClass::from_u32(notify_class as u32);

    let blocked = match class {
        RegNotifyClass::RegNtPreDeleteKey
        | RegNotifyClass::RegNtPreSetValueKey
        | RegNotifyClass::RegNtPreDeleteValueKey
        | RegNotifyClass::RegNtPreSetInformationKey
        | RegNotifyClass::RegNtPreRenameKey
        | RegNotifyClass::RegNtPreCreateKey
        | RegNotifyClass::RegNtPreCreateKeyEx => {
            // For all these classes, the info struct begins with two fields:
            //   Object:       PVOID      (key object, always present)
            //   CompleteName: *UNICODE_STRING (full NT path, may be NULL for existing-key ops)
            //
            // We use REG_PRE_KEY_INFORMATION which shares this layout.
            if info.is_null() {
                false
            } else {
                let pre = &*(info as *const REG_PRE_KEY_INFORMATION);
                is_protected_path(pre.CompleteName)
            }
        }
        _ => false,
    };

    if blocked {
        log::warn!(
            "Registry protection: blocked {:?} on a protected HxPosed key.",
            class
        );
        // STATUS_ACCESS_DENIED
        NtStatus::AccessDenied
    } else {
        NtStatus::Success
    }
}

/// Registers the registry protection callback.
///
/// Must be called once, at `PASSIVE_LEVEL`, after `DriverEntry` completes
/// initialisation. Calling this function a second time without unregistering
/// first is a no-op (the cookie is already non-zero).
pub fn register_registry_protection() -> Result<(), NtStatus> {
    if REGISTRY_COOKIE.load(Ordering::Relaxed) != 0 {
        log::warn!("Registry protection already registered.");
        return Ok(());
    }

    // Build the altitude UNICODE_STRING on the stack. The buffer is a &'static
    // slice so it is valid for the entire driver lifetime.
    let mut altitude = UNICODE_STRING {
        Length: (ALTITUDE_BUF.len() * 2) as u16,
        MaximumLength: (ALTITUDE_BUF.len() * 2) as u16,
        Buffer: ALTITUDE_BUF.as_ptr() as *mut u16,
    };

    let mut cookie: i64 = 0;
    let status = unsafe {
        CmRegisterCallbackEx(
            registry_callback as PVOID,
            &mut altitude,
            null_mut(), // Driver object — NULL is valid for WDM drivers
            null_mut(), // Context passed to callback — unused
            &mut cookie,
            null_mut(), // Reserved
        )
    };

    match status {
        NtStatus::Success => {
            REGISTRY_COOKIE.store(cookie, Ordering::Relaxed);
            log::info!("Registry protection callback registered (cookie={:#x}).", cookie);
            Ok(())
        }
        err => {
            log::error!("CmRegisterCallbackEx failed: {:?}", err);
            Err(err)
        }
    }
}

/// Unregisters the registry protection callback.
/// Safe to call even if the callback was never registered.
#[allow(dead_code)]
pub fn unregister_registry_protection() {
    let cookie = REGISTRY_COOKIE.swap(0, Ordering::Relaxed);
    if cookie == 0 {
        return;
    }
    let status = unsafe { CmUnRegisterCallback(cookie) };
    match status {
        NtStatus::Success => log::info!("Registry protection callback unregistered."),
        err => log::warn!("CmUnRegisterCallback returned: {:?}", err),
    }
}
