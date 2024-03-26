// Copyright (c) iliana destroyer of worlds <iliana@buttslol.net>
// SPDX-License-Identifier: MIT

// Smoke test for the two pub functions in pentacle.
//
// Additional test functions should not be added here due to the test calling CommandExt::exec the
// first time around.

#![warn(clippy::pedantic)]

#[test]
fn main() {
    pentacle::ensure_sealed().unwrap();
    assert!(pentacle::is_sealed());
    assert!(std::env::args().next().unwrap().contains("ensure_sealed"));
}
