// Copyright (c) iliana destroyer of worlds <iliana@buttslol.net>
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

// Test that we can execute a script with a shebang.
#[test]
fn shebang() {
    let mut command = SealedCommand::new(&mut &b"#!/bin/sh\necho 'it works'\n"[..]).unwrap();
    let output = command.output().unwrap();
    eprintln!("{}", String::from_utf8_lossy(&output.stderr));
    assert!(output.status.success());
    assert_eq!(output.stdout, b"it works\n");
}
