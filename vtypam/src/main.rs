//! `vtypam` — minimal PAM authentication helper for zebra-rs.
//!
//! Invoked by the zebra-rs daemon to verify an operator's password when the
//! VTY `enable` command is issued. Kept as a small standalone binary so the
//! daemon does not need the privileges required to read `/etc/shadow`.
//!
//! See `book/src/ch-06-01-session-design.md` (D6, D14, D15) for the full
//! design.
//!
//! ## I/O contract
//!
//! - `argv[1]`: target username.
//! - stdin: password on a single line (trailing newline stripped).
//! - PAM service name: `"zebra-rs"` (set up by the admin under
//!   `/etc/pam.d/zebra-rs`, see `etc/pam.d/zebra-rs.example`).
//!
//! ## Exit codes
//!
//! | Code | Meaning                                            |
//! |------|----------------------------------------------------|
//! |  0   | authentication and account check both succeeded    |
//! |  1   | authentication failure (wrong password, unknown user, etc.) |
//! |  2   | account invalid (expired, locked, denied by acct)  |
//! |  3   | system error (PAM setup failure, syscall failure)  |
//!
//! ## Privilege
//!
//! Installed with `setcap cap_dac_read_search,cap_audit_write=ep` (D15);
//! setuid root is documented as a fallback for distros that strip caps.

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("vtypam: this helper is only supported on Linux");
    std::process::exit(3);
}

#[cfg(target_os = "linux")]
fn main() {
    std::process::exit(linux::run());
}

#[cfg(target_os = "linux")]
mod linux {
    use std::ffi::CString;
    use std::io::{self, BufRead};
    use std::os::raw::{c_char, c_int, c_void};
    use std::ptr;

    // PAM return codes from linux-pam <security/_pam_types.h>. Only the
    // ones we actually branch on.
    const PAM_SUCCESS: c_int = 0;
    const PAM_BUF_ERR: c_int = 5;
    const PAM_PERM_DENIED: c_int = 6;
    const PAM_AUTH_ERR: c_int = 7;
    const PAM_CRED_INSUFFICIENT: c_int = 8;
    const PAM_AUTHINFO_UNAVAIL: c_int = 9;
    const PAM_USER_UNKNOWN: c_int = 10;
    const PAM_MAXTRIES: c_int = 11;
    const PAM_ACCT_EXPIRED: c_int = 13;
    const PAM_CONV_ERR: c_int = 19;

    // Message styles passed to the PAM conversation callback.
    const PAM_PROMPT_ECHO_OFF: c_int = 1;
    const PAM_PROMPT_ECHO_ON: c_int = 2;

    #[repr(C)]
    struct PamMessage {
        msg_style: c_int,
        msg: *const c_char,
    }

    #[repr(C)]
    struct PamResponse {
        resp: *mut c_char,
        resp_retcode: c_int,
    }

    #[repr(C)]
    struct PamConv {
        conv: extern "C" fn(
            num_msg: c_int,
            msg: *mut *const PamMessage,
            resp: *mut *mut PamResponse,
            appdata_ptr: *mut c_void,
        ) -> c_int,
        appdata_ptr: *mut c_void,
    }

    // PAM is opaque to us; just track the handle pointer.
    type PamHandle = *mut c_void;

    #[link(name = "pam")]
    unsafe extern "C" {
        fn pam_start(
            service_name: *const c_char,
            user: *const c_char,
            pam_conv: *const PamConv,
            pamh: *mut PamHandle,
        ) -> c_int;
        fn pam_authenticate(pamh: PamHandle, flags: c_int) -> c_int;
        fn pam_acct_mgmt(pamh: PamHandle, flags: c_int) -> c_int;
        fn pam_end(pamh: PamHandle, pam_status: c_int) -> c_int;
    }

    /// PAM conversation callback. Linux PAM passes `msg` as
    /// `const struct pam_message **` (pointer-to-array-of-pointers).
    ///
    /// Allocates a `PamResponse` array via `libc::calloc` so PAM can `free()`
    /// each entry. For each `PAM_PROMPT_ECHO_OFF` / `PAM_PROMPT_ECHO_ON`
    /// prompt we hand back the cached password (likewise `libc::malloc`'d).
    extern "C" fn conv(
        num_msg: c_int,
        msg: *mut *const PamMessage,
        resp: *mut *mut PamResponse,
        appdata: *mut c_void,
    ) -> c_int {
        if num_msg <= 0 || msg.is_null() || resp.is_null() || appdata.is_null() {
            return PAM_CONV_ERR;
        }

        // SAFETY: appdata is the &Vec<u8> we passed in pam_conv.appdata_ptr.
        let password: &Vec<u8> = unsafe { &*(appdata as *const Vec<u8>) };

        // SAFETY: PAM expects this allocation; it will libc::free each entry.
        let responses = unsafe {
            libc::calloc(
                num_msg as libc::size_t,
                std::mem::size_of::<PamResponse>() as libc::size_t,
            ) as *mut PamResponse
        };
        if responses.is_null() {
            return PAM_BUF_ERR;
        }

        for i in 0..num_msg as isize {
            // SAFETY: msg[i] is one of the PAM-owned message pointers.
            let m_ptr = unsafe { *msg.offset(i) };
            if m_ptr.is_null() {
                continue;
            }
            let style = unsafe { (*m_ptr).msg_style };
            // SAFETY: write into our own allocation.
            let r = unsafe { &mut *responses.offset(i) };

            if style == PAM_PROMPT_ECHO_OFF || style == PAM_PROMPT_ECHO_ON {
                let len = password.len();
                // SAFETY: PAM will libc::free the buffer when it frees the response.
                let buf = unsafe { libc::malloc(len + 1) as *mut c_char };
                if buf.is_null() {
                    // Free what we've allocated so far and bail out.
                    free_response_array(responses, i);
                    return PAM_BUF_ERR;
                }
                unsafe {
                    if len > 0 {
                        ptr::copy_nonoverlapping(password.as_ptr() as *const c_char, buf, len);
                    }
                    *buf.add(len) = 0;
                }
                r.resp = buf;
                r.resp_retcode = 0;
            }
            // PAM_TEXT_INFO / PAM_ERROR_MSG: leave resp as null.
        }

        unsafe { *resp = responses };
        PAM_SUCCESS
    }

    /// Free response slots 0..up_to inclusive, then the array itself.
    fn free_response_array(responses: *mut PamResponse, up_to: isize) {
        unsafe {
            for j in 0..up_to {
                let entry = &mut *responses.offset(j);
                if !entry.resp.is_null() {
                    libc::free(entry.resp as *mut c_void);
                }
            }
            libc::free(responses as *mut c_void);
        }
    }

    pub fn run() -> i32 {
        let user = match std::env::args().nth(1) {
            Some(u) if !u.is_empty() => u,
            _ => {
                eprintln!("vtypam: usage: vtypam <username>");
                return 3;
            }
        };

        let user_c = match CString::new(user.as_bytes()) {
            Ok(c) => c,
            Err(_) => {
                eprintln!("vtypam: username contains NUL");
                return 3;
            }
        };
        let service_c = CString::new("zebra-rs").unwrap();

        let mut password = String::new();
        if let Err(e) = io::stdin().lock().read_line(&mut password) {
            eprintln!("vtypam: failed to read password from stdin: {e}");
            return 3;
        }
        // Strip a single trailing newline; tolerate password with no terminator.
        if password.ends_with('\n') {
            password.pop();
            if password.ends_with('\r') {
                password.pop();
            }
        }
        let password_bytes = password.into_bytes();

        let conv_data = PamConv {
            conv,
            appdata_ptr: &password_bytes as *const Vec<u8> as *mut c_void,
        };

        let mut pamh: PamHandle = ptr::null_mut();
        let rc = unsafe { pam_start(service_c.as_ptr(), user_c.as_ptr(), &conv_data, &mut pamh) };
        if rc != PAM_SUCCESS {
            eprintln!("vtypam: pam_start failed: {rc}");
            return 3;
        }

        let auth_rc = unsafe { pam_authenticate(pamh, 0) };
        let exit = match auth_rc {
            PAM_SUCCESS => {
                let acct_rc = unsafe { pam_acct_mgmt(pamh, 0) };
                match acct_rc {
                    PAM_SUCCESS => 0,
                    PAM_ACCT_EXPIRED | PAM_PERM_DENIED => 2,
                    PAM_USER_UNKNOWN => 1, // unknown user surfaces here for some stacks
                    _ => 3,
                }
            }
            PAM_AUTH_ERR | PAM_CRED_INSUFFICIENT | PAM_USER_UNKNOWN | PAM_MAXTRIES => 1,
            PAM_AUTHINFO_UNAVAIL => 3,
            _ => 3,
        };

        // pam_end returns the last status so PAM modules can act on the
        // session outcome.
        unsafe {
            pam_end(pamh, auth_rc);
        }

        // Zero the in-memory password (best effort; the kernel may have
        // copied it elsewhere already).
        // SAFETY: password_bytes is still owned by us at this point because
        // PAM does not retain the appdata pointer past the conversation.
        let mut pw = password_bytes;
        unsafe {
            ptr::write_bytes(pw.as_mut_ptr(), 0u8, pw.len());
        }
        drop(pw);

        exit
    }
}
