// Violation test for CKSPEC-ARCH-005: Infrastructure independence.
// Infrastructure MUST NOT depend on domain.
// This file MUST fail to compile. If it compiles, the boundary is broken.

use domain::ping::PingResult;

fn main() {
    let _ = PingResult { message: "should not compile".to_string() };
}
