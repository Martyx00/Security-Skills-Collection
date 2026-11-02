//! Rust: unsafe, and the process family.
use std::process::Command;

pub fn run(u: &str) {                                   // EXPECT-FUNC: run
    Command::new("sh").arg("-c").arg(u).output().unwrap();   // EXPECT: INJ-002
}

pub unsafe fn view(p: *const u8, n: usize) -> &'static [u8] {   // EXPECT-FUNC: view
    std::slice::from_raw_parts(p, n)                    // EXPECT: MEM-011
}

pub fn grow(v: &mut Vec<u8>, n: usize) {                // EXPECT-FUNC: grow
    unsafe { v.set_len(n) }                             // EXPECT: MEM-011
}

// Appended below so that nothing citing the lines above moves.

pub fn read_doc(name: &str) -> String {                 // EXPECT-FUNC: read_doc
    std::fs::read_to_string(format!("/srv/docs/{}", name)).unwrap()   // EXPECT: INJ-004
}

pub fn fetch_url(u: &str) -> String {                   // EXPECT-FUNC: fetch_url
    reqwest::blocking::get(u).unwrap().text().unwrap()  // EXPECT: INJ-005
}

pub fn insecure_client() -> Option<Client> {            // EXPECT-FUNC: insecure_client
    Client::builder().danger_accept_invalid_certs(true).build().ok()   // EXPECT: CRY-004
}

// Appended below so that nothing citing the lines above moves. The client
// above is reqwest's, imported by name: `Client::builder()` could be anyone's,
// so this line is the only one in the file that says which crate makes the
// request.
use reqwest::blocking::Client;                          // EXPECT: INJ-005

// Appended below so that nothing citing the lines above moves.
pub fn verify_credentials(user: &str, pass: &str) -> bool {   // EXPECT-FUNC: verify_credentials // EXPECT: LOG-001, LOG-004
    user.len() == pass.len()
}

// Appended below so that nothing citing the lines above moves. ring's
// module-level verify.
pub fn check_update(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {   // EXPECT-FUNC: check_update // EXPECT: LOG-010
    ring::signature::verify(&ED25519, pk, msg, sig).is_ok()     // EXPECT: LOG-004
}
