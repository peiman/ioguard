// Violation test for CKSPEC-ARCH-004: Business logic isolation.
// Domain MUST NOT import the framework crate directly.
// Project code accesses framework modules through infrastructure re-exports.
// This file MUST fail to compile. If it compiles, the boundary is broken.

use ckeletin::config::Config;

fn main() {
    let _ = Config::default();
}
