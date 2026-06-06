// Violation test for CKSPEC-ARCH-003: CLI framework isolation.
// Domain MUST NOT import the CLI framework.
// This file MUST fail to compile. If it compiles, the boundary is broken.

use clap::Parser;

fn main() {}
