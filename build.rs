use std::path::PathBuf;

fn main() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let profile = std::env::var("PROFILE").unwrap();

    // Build the proxy library (always release for small .so size)
    let proxy_dir = manifest.join("oxide-proxy");
    let proxy_target = proxy_dir.join("target");

    let status = std::process::Command::new("cargo")
        .args(["build", "--release"])
        .current_dir(&proxy_dir)
        .env("CARGO_TARGET_DIR", &proxy_target)
        .status()
        .expect("failed to execute cargo build for oxide-proxy");

    assert!(status.success(), "oxide-proxy build failed");

    // Copy liboxide_proxy.so next to the binary
    let so_src = proxy_target.join("release").join("liboxide_proxy.so");
    let so_dst = manifest.join("target").join(&profile).join("liboxide_proxy.so");

    if so_src.exists() {
        std::fs::copy(&so_src, &so_dst).expect("failed to copy liboxide_proxy.so");
        let size = std::fs::metadata(&so_dst).map(|m| m.len()).unwrap_or(0);
        println!("cargo:warning=liboxide_proxy.so ({}) copied to target/{}/", size, profile);
    } else {
        panic!("oxide-proxy build did not produce liboxide_proxy.so at {:?}", so_src);
    }
}
