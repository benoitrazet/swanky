use std::sync::atomic::AtomicBool;

pub(super) fn warn_vulnerabilities() {
    static WARNING_PRINTED: AtomicBool = AtomicBool::new(false);
    if !WARNING_PRINTED.swap(true, std::sync::atomic::Ordering::Relaxed) {
        eprintln!("SWANKY SECURITY WARNING:");
        eprintln!("This code suffers from several vulnerabilities, documented in");
        eprintln!("Issues #39, #40, #41 on GitHub. Until those vulnerabilities are");
        eprintln!("addressed, it is best to avoid using this implementation.");
    }
}
