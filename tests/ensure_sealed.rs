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
    assert_eq!(pentacle::is_sealed(), true);
    assert!(std::env::args().next().unwrap().contains("ensure_sealed"));
}
