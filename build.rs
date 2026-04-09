use std::process::Command;

fn main() {
    // Get the git commit hash
    let commit = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    // Check if HEAD has a tag
    let tag = Command::new("git")
        .args(["tag", "--points-at", "HEAD"])
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    // Check current branch
    let branch = Command::new("git")
        .args(["branch", "--show-current"])
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    // Set environment variables for the build
    println!("cargo:rustc-env=GUARD_GIT_COMMIT={}", commit);
    println!("cargo:rustc-env=GUARD_GIT_BRANCH={}", branch);

    if let Some(tag) = tag {
        println!("cargo:rustc-env=GUARD_GIT_TAG={}", tag);
    }

    // Rebuild if git changes
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs/");
}
