// Violation test for CKSPEC-ARCH-004: Business logic isolation.
// Domain MUST NOT import infrastructure concerns like tracing.
// This file MUST fail to compile. If it compiles, the boundary is broken.

use tracing::info;

fn main() {
    info!("this should not compile in domain");
}
