// Violation test for CKSPEC-ARCH-004 + ARCH-002: Directed dependencies.
// Domain MUST NOT depend on infrastructure crate.
// This file MUST fail to compile. If it compiles, the boundary is broken.

use infrastructure::output::Output;

fn main() {
    let _ = Output::new(infrastructure::output::OutputMode::Human);
}
