mod args;
mod crypto;
mod pubkey;
mod secure;
mod tpm;

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};
use std::ptr;

use args::parse_args;
use secure::{zeroize_c_string, SecureBuffer};

pub fn diagnostic_sign(
    pin: &[u8],
    key_handle: u32,
    tcti: &str,
) -> Result<[u8; crypto::RAW_SIGNATURE_SIZE], Box<dyn std::error::Error>> {
    let challenge = crypto::generate_challenge()?;
    Ok(tpm::sign_challenge(tcti, key_handle, pin, &challenge)?)
}

const PAM_SUCCESS: c_int = 0;
const PAM_SERVICE_ERR: c_int = 3;
const PAM_AUTH_ERR: c_int = 7;
const PAM_CONV: c_int = 5;
const PAM_PROMPT_ECHO_OFF: c_int = 1;

#[repr(C)]
pub struct PamHandle {
    _private: [u8; 0],
}

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

type PamConvFn = unsafe extern "C" fn(
    c_int,
    *mut *const PamMessage,
    *mut *mut PamResponse,
    *mut c_void,
) -> c_int;

#[repr(C)]
struct PamConv {
    conv: Option<PamConvFn>,
    appdata_ptr: *mut c_void,
}

#[link(name = "pam")]
extern "C" {
    fn pam_get_item(pamh: *mut PamHandle, item_type: c_int, item: *mut *const c_void) -> c_int;
}

#[no_mangle]
pub extern "C" fn pam_sm_authenticate(
    pamh: *mut PamHandle,
    _flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    match authenticate(pamh, argc, argv) {
        Ok(()) => {
            log_info("TPM ECC authentication succeeded");
            PAM_SUCCESS
        }
        Err(AuthError::Service(message)) => {
            log_err(&message);
            PAM_SERVICE_ERR
        }
        Err(AuthError::Auth(message)) => {
            log_err(&message);
            PAM_AUTH_ERR
        }
    }
}

#[derive(Debug)]
enum AuthError {
    Service(String),
    Auth(String),
}

fn authenticate(
    pamh: *mut PamHandle,
    argc: c_int,
    argv: *const *const c_char,
) -> Result<(), AuthError> {
    let args = pam_args(argc, argv)?;
    let arg_refs = args.iter().map(String::as_str).collect::<Vec<_>>();
    let config = parse_args(&arg_refs).map_err(|err| AuthError::Service(err.to_string()))?;
    let public_key = pubkey::load_public_key(&config.pubkey)
        .map_err(|err| AuthError::Service(err.to_string()))?;
    let pin = prompt_pin(pamh)?;
    let mut challenge = SecureBuffer::new(crypto::CHALLENGE_SIZE);
    if !challenge.locked() {
        log_warn("mlock failed for challenge buffer; continuing");
    }
    challenge.copy_from_slice(
        &crypto::generate_challenge().map_err(|err| AuthError::Auth(err.to_string()))?,
    );

    let signature = tpm::sign_challenge(&config.tcti, config.key_handle, &pin, &challenge)
        .map_err(|err| AuthError::Auth(err.to_string()))?;
    let signature = SecureBuffer::from_slice(&signature);
    if !signature.locked() {
        log_warn("mlock failed for signature buffer; continuing");
    }

    crypto::verify_challenge(&public_key, &challenge, &signature)
        .map_err(|err| AuthError::Auth(err.to_string()))
}

fn pam_args(argc: c_int, argv: *const *const c_char) -> Result<Vec<String>, AuthError> {
    if argc < 0 {
        return Err(AuthError::Service("negative argc from PAM".to_string()));
    }
    if argc > 0 && argv.is_null() {
        return Err(AuthError::Service("argv is NULL".to_string()));
    }

    let mut out = Vec::with_capacity(argc as usize);
    for idx in 0..argc as isize {
        let ptr = unsafe { *argv.offset(idx) };
        if ptr.is_null() {
            continue;
        }
        let arg = unsafe { CStr::from_ptr(ptr) }
            .to_str()
            .map_err(|_| AuthError::Service("PAM argument is not UTF-8".to_string()))?;
        out.push(arg.to_string());
    }

    Ok(out)
}

fn prompt_pin(pamh: *mut PamHandle) -> Result<SecureBuffer, AuthError> {
    if pamh.is_null() {
        return Err(AuthError::Service("pamh is NULL".to_string()));
    }

    let mut item: *const c_void = ptr::null();
    let ret = unsafe { pam_get_item(pamh, PAM_CONV, &mut item) };
    if ret != PAM_SUCCESS || item.is_null() {
        return Err(AuthError::Service(
            "no PAM conversation function".to_string(),
        ));
    }

    let conv = unsafe { &*(item as *const PamConv) };
    let conv_fn = conv
        .conv
        .ok_or_else(|| AuthError::Service("no PAM conversation function".to_string()))?;

    let prompt = CString::new("[TPM] authenticate: ").unwrap();
    let message = PamMessage {
        msg_style: PAM_PROMPT_ECHO_OFF,
        msg: prompt.as_ptr(),
    };
    let mut message_ptr: *const PamMessage = &message;
    let mut response_ptr: *mut PamResponse = ptr::null_mut();

    let ret = unsafe { conv_fn(1, &mut message_ptr, &mut response_ptr, conv.appdata_ptr) };
    if ret != PAM_SUCCESS || response_ptr.is_null() {
        return Err(AuthError::Auth("conversation failed".to_string()));
    }

    let response = unsafe { &mut *response_ptr };
    if response.resp.is_null() {
        unsafe {
            libc::free(response_ptr.cast::<c_void>());
        }
        return Ok(SecureBuffer::new(0));
    }

    let pin = unsafe { SecureBuffer::from_slice(CStr::from_ptr(response.resp).to_bytes()) };
    if !pin.locked() && !pin.is_empty() {
        log_warn("mlock failed for PIN buffer; continuing");
    }

    unsafe {
        zeroize_c_string(response.resp);
        libc::free(response.resp.cast::<c_void>());
        libc::free(response_ptr.cast::<c_void>());
    }

    Ok(pin)
}

fn log_err(message: &str) {
    syslog(libc::LOG_ERR, message);
}

fn log_warn(message: &str) {
    syslog(libc::LOG_WARNING, message);
}

fn log_info(message: &str) {
    syslog(libc::LOG_INFO, message);
}

fn syslog(priority: c_int, message: &str) {
    let Ok(fmt) = CString::new("%s") else {
        return;
    };
    let sanitized = message.replace('\0', "\\0");
    let Ok(msg) = CString::new(sanitized) else {
        return;
    };
    unsafe {
        libc::syslog(priority, fmt.as_ptr(), msg.as_ptr());
    }
}

#[no_mangle]
pub extern "C" fn pam_sm_setcred(
    _pamh: *mut PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_SUCCESS
}

#[no_mangle]
pub extern "C" fn pam_sm_acct_mgmt(
    _pamh: *mut PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_SUCCESS
}

#[no_mangle]
pub extern "C" fn pam_sm_open_session(
    _pamh: *mut PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_SUCCESS
}

#[no_mangle]
pub extern "C" fn pam_sm_close_session(
    _pamh: *mut PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_SUCCESS
}

#[no_mangle]
pub extern "C" fn pam_sm_chauthtok(
    _pamh: *mut PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_SUCCESS
}
