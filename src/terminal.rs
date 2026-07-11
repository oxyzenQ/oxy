// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Terminal alternate screen mode — like htop/vim/less.
//!
//! Uses the terminal's alternate screen buffer (xterm ESC[?1049h).
//! Content is rendered on the alt screen; when zelynic exits, the
//! original screen is restored — no trace left in scrollback.

use anyhow::Result;
use std::io::{self, Read, Write};
use std::time::{Duration, Instant};

/// Terminal guard — enters alt screen + raw mode, restores on drop.
pub struct AltScreen {
    original: nix::sys::termios::Termios,
}

impl AltScreen {
    pub fn enter() -> Result<Self> {
        use nix::sys::termios::*;
        let stdin = io::stdin();
        let original = tcgetattr(&stdin)?;

        let mut raw = original.clone();
        raw.local_flags &= !(LocalFlags::ICANON | LocalFlags::ECHO);
        raw.control_chars[SpecialCharacterIndices::VMIN as usize] = 0;
        raw.control_chars[SpecialCharacterIndices::VTIME as usize] = 0;

        tcsetattr(&stdin, SetArg::TCSANOW, &raw)?;

        // Enter alternate screen + hide cursor
        // ESC[?1049h = save cursor + switch to alt screen + clear it
        // ESC[?25l = hide cursor
        print!("\x1b[?1049h\x1b[?25l");
        io::stdout().flush()?;

        Ok(AltScreen { original })
    }
}

impl Drop for AltScreen {
    fn drop(&mut self) {
        use nix::sys::termios::*;
        let stdin = io::stdin();
        let _ = tcsetattr(&stdin, SetArg::TCSANOW, &self.original);

        // Leave alternate screen + show cursor
        // ESC[?1049l = switch back to main screen + restore cursor
        // ESC[?25h = show cursor
        print!("\x1b[?1049l\x1b[?25h");
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

/// Clear screen and move cursor to top-left (on alt screen).
pub fn clear_screen() {
    print!("\x1b[2J\x1b[H");
}

/// Run an alternate-screen loop.
///
/// Renders content on the alt screen, refreshing every `refresh_interval`.
/// Exits on q/ESC/Ctrl+C or after `duration` (ZERO = forever).
/// On exit, the original terminal screen is restored — no trace in scrollback.
pub fn run_alt<F>(refresh_interval: Duration, duration: Duration, mut render: F)
where
    F: FnMut(),
{
    let _screen = match AltScreen::enter() {
        Ok(g) => g,
        Err(_) => {
            // Fallback: simple loop (no alt screen, no key handling)
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
    let mut last_render = Instant::now() - refresh_interval; // render immediately on first iteration

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
