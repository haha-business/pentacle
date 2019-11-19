// Copyright (c) 2019 iliana destroyer of worlds <iliana@buttslol.net>
// SPDX-License-Identifier: MIT

#![warn(clippy::pedantic)]

use pentacle::SealedCommand;
use std::fs::File;
use std::io::Result;

// Test that a SealedCommand can be spawned more than once.
#[test]
fn so_nice_we_ran_it_twice() -> Result<()> {
    let mut command = SealedCommand::new(&mut File::open("/bin/sh")?)?;
    command.arg("-c").arg("/bin/true");
    for _ in 0..2 {
        assert!(command.output()?.status.success());
    }
    Ok(())
}
