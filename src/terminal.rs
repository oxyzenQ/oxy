// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Terminal box mode — in-place refresh without scrollback spam.
//!
//! NOT a TUI. Just clears screen + redraws content in place.
//! Exit with q, ESC, or Ctrl+C.

use anyhow::Result;
use std::io::{self, Read, Write};
use std::time::{Duration, Instant};

/// Terminal guard — enters raw mode on creation, restores on drop.
pub struct RawMode {
    original: nix::sys::termios::Termios,
}

impl RawMode {
    pub fn enter() -> Result<Self> {
        use nix::sys::termios::*;
        let stdin = io::stdin();
        let original = tcgetattr(&stdin)?;

        let mut raw = original.clone();
        raw.local_flags &= !(LocalFlags::ICANON | LocalFlags::ECHO);
        raw.control_chars[SpecialCharacterIndices::VMIN as usize] = 0;
        raw.control_chars[SpecialCharacterIndices::VTIME as usize] = 0;

        tcsetattr(&stdin, SetArg::TCSANOW, &raw)?;

        // Hide cursor
        print!("\x1b[?25l");
        io::stdout().flush()?;

        Ok(RawMode { original })
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        use nix::sys::termios::*;
        let stdin = io::stdin();
        let _ = tcsetattr(&stdin, SetArg::TCSANOW, &self.original);

        // Show cursor + clear screen
        print!("\x1b[?25h\x1b[2J\x1b[H");
        let _ = io::stdout().flush();
    }
}

/// Check if q/ESC/Ctrl+C was pressed (non-blocking).
pub fn should_quit() -> bool {
    let mut buf = [0u8; 1];
    if let Ok(n) = io::stdin().read(&mut buf) {
        if n > 0 {
            return buf[0] == b'q' || buf[0] == 0x1b || buf[0] == 0x03;
        }
    }
    false
}

/// Clear screen and move cursor to top-left.
pub fn clear_screen() {
    print!("\x1b[2J\x1b[H");
}

/// Run a box-mode loop. Calls `render` every `refresh_interval`, exits on
/// q/ESC/Ctrl+C or after `duration` (ZERO = forever).
pub fn run_box<F>(refresh_interval: Duration, duration: Duration, mut render: F)
where
    F: FnMut(),
{
    let _raw = match RawMode::enter() {
        Ok(g) => g,
        Err(_) => {
            // Fallback: simple loop without key handling
            let start = Instant::now();
            loop {
                clear_screen();
                render();
                io::stdout().flush().ok();

                if duration > Duration::ZERO && start.elapsed() >= duration {
                    break;
                }
                std::thread::sleep(refresh_interval);
            }
            return;
        }
    };

    let start = Instant::now();
    let mut last_render = Instant::now();

    loop {
        if should_quit() {
            break;
        }

        if duration > Duration::ZERO && start.elapsed() >= duration {
            break;
        }

        if last_render.elapsed() >= refresh_interval {
            clear_screen();
            render();
            io::stdout().flush().ok();
            last_render = Instant::now();
        }

        std::thread::sleep(Duration::from_millis(50));
    }
}
