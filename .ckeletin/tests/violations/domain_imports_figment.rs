// Violation test for CKSPEC-ARCH-004: Business logic isolation.
// Domain MUST NOT import configuration infrastructure.
// This file MUST fail to compile. If it compiles, the boundary is broken.

use figment::Figment;

fn main() {
    let _ = Figment::new();
}
