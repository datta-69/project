mod analyzer;
mod app;
mod collector;
mod gpu;
mod logger;
mod models;
mod ui;

use app::App;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use directories::ProjectDirs;
use ratatui::{backend::CrosstermBackend, Terminal};
use std::fs::OpenOptions;
use std::path::PathBuf;
use std::{io, time::Duration};

#[derive(Default)]
struct TerminalGuard {
    raw_enabled: bool,
    alt_screen_enabled: bool,
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        if self.alt_screen_enabled {
            let mut stdout = io::stdout();
            let _ = execute!(stdout, LeaveAlternateScreen, DisableMouseCapture);
        }
        if self.raw_enabled {
            let _ = disable_raw_mode();
        }
    }
}

fn log_file_candidates() -> Vec<PathBuf> {
    let mut out = Vec::with_capacity(5);

    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            out.push(parent.join("process_monitor.log"));
        }
    }

    if let Some(project_dirs) = ProjectDirs::from("com", "ProcessMonitor", "process_monitor") {
        out.push(
            project_dirs
                .data_local_dir()
                .join("logs")
                .join("process_monitor.log"),
        );
        out.push(project_dirs.cache_dir().join("process_monitor.log"));
    }

    out.push(PathBuf::from("process_monitor.log"));
    out
}

fn open_log_file() -> io::Result<(std::fs::File, PathBuf)> {
    let mut last_err: Option<io::Error> = None;

    for path in log_file_candidates() {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        match OpenOptions::new().create(true).append(true).open(&path) {
            Ok(file) => return Ok((file, path)),
            Err(e) => last_err = Some(e),
        }
    }

    Err(last_err.unwrap_or_else(|| io::Error::other("No writable log path found")))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Logging must not write to stdout/stderr while TUI is active (it corrupts the screen).
    // Write logs to the first writable path from a platform-aware list.
    let (log_file, log_path) =
        open_log_file().map_err(|e| format!("Failed to open any log file path: {}", e))?;

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .target(env_logger::Target::Pipe(Box::new(log_file)))
        .format_timestamp_secs()
        .init();

    eprintln!("Logging to: {}", log_path.display());

    // Setup Terminal (guarded so partial setup failures still restore terminal state)
    let mut guard = TerminalGuard::default();
    enable_raw_mode().map_err(|e| format!("Failed to enable raw mode: {}", e))?;
    guard.raw_enabled = true;

    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)
        .map_err(|e| format!("Failed to setup terminal: {}", e))?;
    guard.alt_screen_enabled = true;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal =
        Terminal::new(backend).map_err(|e| format!("Failed to create terminal: {}", e))?;

    // Create App State
    let mut app = App::new();

    // Main Loop
    let res = run_app(&mut terminal, &mut app);

    // Restore cursor immediately; raw/alt cleanup is handled by guard Drop.
    terminal.show_cursor()?;

    if let Err(err) = res {
        eprintln!("Application error: {:?}", err);
        eprintln!("Check log for details: {}", log_path.display());
        return Err(err.into());
    }

    drop(terminal);
    drop(guard);

    Ok(())
}

fn run_app<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    app: &mut App,
) -> io::Result<()>
where
    std::io::Error: From<B::Error>, // Ensure backend errors can convert to io::Error
{
    let tick_rate = Duration::from_millis(1000); // 1s update balances smoothness and CPU usage
    let mut last_tick = std::time::Instant::now();

    loop {
        terminal.draw(|f| ui::ui(f, app))?;

        let timeout = tick_rate
            .checked_sub(last_tick.elapsed())
            .unwrap_or_else(|| Duration::from_secs(0));

        if crossterm::event::poll(timeout)? {
            match event::read()? {
                Event::Key(key) => {
                    // On Windows terminals we can receive key release events; ignore those.
                    if matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) {
                        app.on_key(key);
                    }
                }
                Event::Resize(_, _) => {
                    // Re-draw happens each loop anyway.
                }
                _ => {}
            }
        }

        if last_tick.elapsed() >= tick_rate {
            app.on_tick();
            last_tick = std::time::Instant::now();
        }

        if app.should_quit {
            return Ok(());
        }
    }
}
