use crate::app::App;
use crate::models::RiskLevel;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        Axis, Block, Borders, Chart, Dataset, Gauge, GraphType, List, ListItem, Paragraph, Row,
        Table, Tabs,
    },
    Frame,
};
use std::collections::VecDeque;

pub fn ui(f: &mut Frame, app: &mut App) {
    let size = f.area();

    // Vertical layout: Tabs (Menu) | Main Content | Logs/Status
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(
            [
                Constraint::Length(3),  // Tabs
                Constraint::Min(0),     // Main content
                Constraint::Length(10), // Logs
            ]
            .as_ref(),
        )
        .split(size);

    // 1. Draw Tabs
    let titles: Vec<Line> = ["Dashboard", "Processes", "Graphs", "Help"]
        .iter()
        .map(|t| Line::from(Span::styled(*t, Style::default().fg(Color::White))))
        .collect();

    let tabs = Tabs::new(titles)
        .block(Block::default().borders(Borders::ALL).title(format!(
            "Intelligent Process Monitor [Tab {}/4]",
            app.selected_tab + 1
        )))
        .highlight_style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD)
                .add_modifier(Modifier::REVERSED),
        )
        .select(app.selected_tab)
        .divider(" | ");

    f.render_widget(tabs, chunks[0]);

    // 2. Draw Main Content based on Tab
    match app.selected_tab {
        0 => draw_dashboard(f, app, chunks[1]),
        1 => draw_process_list(f, app, chunks[1]),
        2 => draw_graphs(f, app, chunks[1]),
        3 => draw_help(f, chunks[1]),
        _ => {}
    }

    // 3. Draw Event Logs (Always visible at bottom)
    draw_logs(f, app, chunks[2]);

    // Show current tab info in title
    let tab_name = match app.selected_tab {
        0 => "Dashboard",
        1 => "Processes",
        2 => "Graphs",
        3 => "Help",
        _ => "Unknown",
    };
    let _ = tab_name; // Used in title above
}

fn draw_dashboard(f: &mut Frame, app: &App, area: Rect) {
    // Split into 3 vertical panes: Stats | Top Risk Process | Quick Graph
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints(
            [
                Constraint::Percentage(30),
                Constraint::Percentage(40),
                Constraint::Percentage(30),
            ]
            .as_ref(),
        )
        .split(area);

    // Pane 1: System Overview (live; separate from Event Log)
    let (used_mem, total_mem) = app.collector.get_memory_stats();
    let total_mem = total_mem.max(1);
    let mem_percent = (used_mem as f64 / total_mem as f64) * 100.0;
    let cpu_percent = app.collector.get_global_cpu_usage().clamp(0.0, 100.0) as f64;
    let total_procs = app.processes.len();
    let high_risks = app
        .processes
        .iter()
        .filter(|p| matches!(p.current_risk.level, RiskLevel::High | RiskLevel::Critical))
        .count();

    let overview_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(7),      // header
            Constraint::Percentage(40), // disks
            Constraint::Percentage(30), // gpu
            Constraint::Min(3),         // totals
        ])
        .split(chunks[0]);

    let header_text = vec![
        Line::from(vec![
            Span::raw("OS: "),
            Span::styled(
                &app.os_info,
                Style::default()
                    .add_modifier(Modifier::BOLD)
                    .fg(Color::Green),
            ),
        ]),
        Line::from(vec![
            Span::raw("Host: "),
            Span::styled(&app.host_name, Style::default().fg(Color::Blue)),
        ]),
        Line::from(vec![
            Span::raw("Disk: "),
            Span::styled(&app.disk_usage_text, Style::default().fg(Color::Magenta)),
        ]),
        Line::from(vec![
            Span::raw("CPU Freq: "),
            Span::styled(
                app.cpu_freq_mhz
                    .map(|v| format!("{} MHz", v))
                    .unwrap_or_else(|| "N/A".to_string()),
                Style::default().fg(Color::Cyan),
            ),
        ]),
        Line::from(vec![
            Span::raw("RAM Speed: "),
            Span::styled(
                app.ram_speed_mhz
                    .map(|v| format!("{} MHz", v))
                    .unwrap_or_else(|| "N/A".to_string()),
                Style::default().fg(Color::Yellow),
            ),
        ]),
        Line::from(vec![
            Span::raw("Uptime: "),
            Span::styled(format!("{}s", app.uptime), Style::default().fg(Color::Gray)),
        ]),
        Line::from(vec![
            Span::raw("Last tick: "),
            Span::styled(
                format!("{:.0}", app.tick_count),
                Style::default().fg(Color::Gray),
            ),
        ]),
    ];
    let header = Paragraph::new(header_text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("System Overview"),
        )
        .style(Style::default().fg(Color::White));
    f.render_widget(header, overview_chunks[0]);

    // Disks: all partitions
    let disk_lines = app.collector.get_all_disks_lines();
    let mut disk_items: Vec<ListItem> = disk_lines
        .into_iter()
        .map(|l| ListItem::new(l).style(Style::default().fg(Color::White)))
        .collect();
    if disk_items.is_empty() {
        disk_items.push(ListItem::new("No disks found").style(Style::default().fg(Color::Gray)));
    }
    let disk_list = List::new(disk_items).block(
        Block::default()
            .borders(Borders::ALL)
            .title("Disks (All Partitions)"),
    );
    f.render_widget(disk_list, overview_chunks[1]);

    // GPU: all adapters + best-effort utilization/memory (Windows WMI)
    let mut gpu_items: Vec<ListItem> = app
        .gpu_adapters
        .iter()
        .map(|g| {
            ListItem::new(format!("{}  [{} | {}]", g.name, g.backend, g.device_type))
                .style(Style::default().fg(Color::Cyan))
        })
        .collect();
    if gpu_items.is_empty() {
        gpu_items.push(
            ListItem::new("No GPU adapters detected").style(Style::default().fg(Color::Gray)),
        );
    }

    let gpu_title = if let Some(s) = &app.gpu_stats {
        let util = s
            .utilization_percent
            .map(|v| format!("{:.0}%", v))
            .unwrap_or_else(|| "N/A".to_string());

        let vram = match (s.dedicated_used_mib, s.dedicated_total_mib) {
            (Some(u), Some(t)) if t > 0.0 => format!("{:.0}/{:.0} MiB", u, t),
            _ => "N/A".to_string(),
        };
        format!("GPU (Adapters)  Load {}  VRAM {}", util, vram)
    } else {
        "GPU (Adapters)".to_string()
    };
    let gpu_list =
        List::new(gpu_items).block(Block::default().borders(Borders::ALL).title(gpu_title));
    f.render_widget(gpu_list, overview_chunks[2]);

    let mem_gb_used = used_mem as f64 / 1_048_576.0;
    let mem_gb_total = total_mem as f64 / 1_048_576.0;
    let footer_text = vec![
        Line::from(vec![
            Span::raw("Processes: "),
            Span::styled(total_procs.to_string(), Style::default().fg(Color::Cyan)),
        ]),
        Line::from(vec![
            Span::raw("High Risks: "),
            Span::styled(high_risks.to_string(), Style::default().fg(Color::Red)),
        ]),
        Line::from(vec![
            Span::raw("Memory: "),
            Span::styled(
                format!("{:.1}/{:.1} GiB", mem_gb_used, mem_gb_total),
                Style::default().fg(Color::Yellow),
            ),
        ]),
    ];
    let footer = Paragraph::new(footer_text)
        .block(Block::default().borders(Borders::ALL).title("Totals"))
        .style(Style::default().fg(Color::White));
    f.render_widget(footer, overview_chunks[3]);

    // Pane 2: Top Risk + Top GPU + Top VRAM
    let middle_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(34),
            Constraint::Percentage(33),
            Constraint::Percentage(33),
        ])
        .split(chunks[1]);

    // Top Risk Processes (always show top N, even if all are Low)
    let mut by_risk: Vec<&crate::models::MonitoredProcess> = app.processes.iter().collect();
    by_risk.sort_by(|a, b| {
        b.current_risk
            .score
            .cmp(&a.current_risk.score)
            .then_with(|| b.metadata.pid.cmp(&a.metadata.pid))
    });

    let mut risk_items: Vec<ListItem> = by_risk
        .into_iter()
        .take(10)
        .map(|p| {
            let color = match p.current_risk.level {
                RiskLevel::Critical => Color::Red,
                RiskLevel::High => Color::Magenta,
                RiskLevel::Medium => Color::Yellow,
                RiskLevel::Low => Color::Green,
            };
            let last_metrics = p.metrics_history.back().map(|x| &x.1);
            let cpu = last_metrics.map(|m| m.cpu_usage).unwrap_or(0.0);
            let mem_mib = last_metrics.map(|m| m.memory_mib()).unwrap_or(0.0);
            ListItem::new(format!(
                "[{}] {:<22}  risk {:>3}  cpu {:>5.1}%  mem {:>6.0} MiB",
                p.metadata.pid,
                p.metadata.name.chars().take(22).collect::<String>(),
                p.current_risk.score,
                cpu,
                mem_mib
            ))
            .style(Style::default().fg(color))
        })
        .collect();

    if risk_items.is_empty() {
        risk_items
            .push(ListItem::new("Collecting processes...").style(Style::default().fg(Color::Gray)));
    }

    let risk_list = List::new(risk_items).block(
        Block::default()
            .borders(Borders::ALL)
            .title("Top Risk Processes"),
    );
    f.render_widget(risk_list, middle_chunks[0]);

    // Top GPU Processes (best-effort)
    let mut gpu_items: Vec<ListItem> = Vec::new();
    if app.gpu_process_usage.is_empty() {
        gpu_items.push(
            ListItem::new("GPU per-process usage not available")
                .style(Style::default().fg(Color::Gray)),
        );
    } else {
        let mut by_gpu: Vec<(&crate::models::MonitoredProcess, f64)> = app
            .processes
            .iter()
            .map(|p| {
                let gpu = app
                    .gpu_process_usage
                    .get(&p.metadata.pid)
                    .copied()
                    .unwrap_or(0.0);
                (p, gpu)
            })
            .collect();
        by_gpu.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        gpu_items = by_gpu
            .into_iter()
            .take(10)
            .map(|(p, gpu)| {
                let color = if gpu >= 50.0 {
                    Color::Magenta
                } else if gpu >= 10.0 {
                    Color::Yellow
                } else {
                    Color::Cyan
                };
                ListItem::new(format!(
                    "[{}] {:<22}  gpu {:>5.1}%",
                    p.metadata.pid,
                    p.metadata.name.chars().take(22).collect::<String>(),
                    gpu
                ))
                .style(Style::default().fg(color))
            })
            .collect();
    }

    let gpu_list = List::new(gpu_items).block(
        Block::default()
            .borders(Borders::ALL)
            .title("Top GPU Processes (Best-effort)"),
    );
    f.render_widget(gpu_list, middle_chunks[1]);

    // Top VRAM Processes (best-effort)
    let mut vram_items: Vec<ListItem> = Vec::new();
    if app.gpu_process_memory.is_empty() {
        vram_items.push(
            ListItem::new("GPU per-process memory not available")
                .style(Style::default().fg(Color::Gray)),
        );
    } else {
        let mut by_vram: Vec<(&crate::models::MonitoredProcess, f64)> = app
            .processes
            .iter()
            .map(|p| {
                let vram = app
                    .gpu_process_memory
                    .get(&p.metadata.pid)
                    .and_then(|m| m.dedicated_used_mib)
                    .unwrap_or(0.0);
                (p, vram)
            })
            .collect();
        by_vram.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        vram_items = by_vram
            .into_iter()
            .take(10)
            .map(|(p, vram)| {
                let color = if vram >= 1024.0 {
                    Color::Magenta
                } else if vram >= 256.0 {
                    Color::Yellow
                } else {
                    Color::Cyan
                };
                ListItem::new(format!(
                    "[{}] {:<22}  vram {:>6.0} MiB",
                    p.metadata.pid,
                    p.metadata.name.chars().take(22).collect::<String>(),
                    vram
                ))
                .style(Style::default().fg(color))
            })
            .collect();
    }

    let vram_list = List::new(vram_items).block(
        Block::default()
            .borders(Borders::ALL)
            .title("Top VRAM Processes (Best-effort)"),
    );
    f.render_widget(vram_list, middle_chunks[2]);

    // Pane 3: CPU/RAM/GPU live panels (separate from Event Log)
    let right_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),      // CPU gauge
            Constraint::Percentage(26), // CPU chart
            Constraint::Length(3),      // RAM gauge
            Constraint::Percentage(26), // RAM chart
            Constraint::Length(3),      // GPU gauge
            Constraint::Percentage(48), // GPU chart
        ])
        .split(chunks[2]);

    let cpu_g2 = Gauge::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("CPU Load (Now)"),
        )
        .gauge_style(Style::default().fg(Color::Cyan))
        .ratio((cpu_percent / 100.0).clamp(0.0, 1.0))
        .label(format!("{:.1}%", cpu_percent));
    f.render_widget(cpu_g2, right_chunks[0]);
    draw_mini_chart(
        f,
        &app.cpu_history,
        right_chunks[1],
        "CPU Load (%)",
        Color::Cyan,
    );

    let mem_g2 = Gauge::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("RAM Usage (Now)"),
        )
        .gauge_style(Style::default().fg(Color::LightGreen))
        .ratio((mem_percent / 100.0).clamp(0.0, 1.0))
        .label(format!("{:.1}%", mem_percent));
    f.render_widget(mem_g2, right_chunks[2]);
    draw_mini_chart(
        f,
        &app.ram_history,
        right_chunks[3],
        "RAM Usage (%)",
        Color::LightGreen,
    );

    let gpu_percent = app
        .gpu_stats
        .as_ref()
        .and_then(|s| s.utilization_percent)
        .unwrap_or(0.0)
        .clamp(0.0, 100.0);
    let gpu_g2 = Gauge::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("GPU Load (Now)"),
        )
        .gauge_style(Style::default().fg(Color::Magenta))
        .ratio((gpu_percent / 100.0).clamp(0.0, 1.0))
        .label(format!("{:.1}%", gpu_percent));
    f.render_widget(gpu_g2, right_chunks[4]);
    draw_mini_chart(
        f,
        &app.gpu_history,
        right_chunks[5],
        "GPU Load (%)",
        Color::Magenta,
    );
}

fn draw_process_list(f: &mut Frame, app: &mut App, area: Rect) {
    // Safety check: if no processes, show message
    if app.processes.is_empty() {
        let msg = Paragraph::new("Loading processes...")
            .block(Block::default().borders(Borders::ALL).title("Process List"))
            .style(Style::default().fg(Color::Yellow));
        f.render_widget(msg, area);
        return;
    }

    // Layout: Header | Body (Table | Details)
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0)].as_ref())
        .split(area);

    let sort_text = format!(
        "Sort: {:?} {}  |  s: cycle sort  r: reverse  ↑/↓: select  Tab: switch  q: quit",
        app.sort_by,
        if app.sort_desc { "(desc)" } else { "(asc)" }
    );
    let header = Paragraph::new(Line::from(vec![
        Span::styled(
            "Processes",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled(sort_text, Style::default().fg(Color::Gray)),
    ]))
    .block(Block::default().borders(Borders::ALL));
    f.render_widget(header, chunks[0]);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(65), Constraint::Percentage(35)].as_ref())
        .split(chunks[1]);

    let rows: Vec<Row> = app
        .processes
        .iter()
        .map(|p| {
            let risk_style = match p.current_risk.level {
                RiskLevel::Critical => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                RiskLevel::High => Style::default().fg(Color::Magenta),
                RiskLevel::Medium => Style::default().fg(Color::Yellow),
                _ => Style::default().fg(Color::White), // White is better for reading normal processes
            };

            let last_metrics = p.metrics_history.back().map(|x| &x.1);
            let cpu = last_metrics.map(|m| m.cpu_usage).unwrap_or(0.0);
            let mem_mib = last_metrics.map(|m| m.memory_mib() as u64).unwrap_or(0);
            let status = last_metrics.map(|m| m.status.as_str()).unwrap_or("-");
            let user = p.metadata.uid.as_deref().unwrap_or("-");

            let gpu_opt = app.gpu_process_usage.get(&p.metadata.pid).copied();

            let vram_opt = app
                .gpu_process_memory
                .get(&p.metadata.pid)
                .and_then(|m| m.dedicated_used_mib);

            Row::new(vec![
                format!("{}", p.metadata.pid),
                p.metadata.name.clone(),
                format!("{:.1}%", cpu),
                gpu_opt
                    .map(|v| format!("{:.1}%", v.clamp(0.0, 100.0)))
                    .unwrap_or_else(|| "-".to_string()),
                vram_opt
                    .map(|v| format!("{:.0} MiB", v.max(0.0)))
                    .unwrap_or_else(|| "-".to_string()),
                format!("{} MiB", mem_mib),
                status.to_string(),
                user.to_string(),
                format!("{}", p.current_risk.score),
            ])
            .style(risk_style)
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(8),
            Constraint::Percentage(26),
            Constraint::Length(8),
            Constraint::Length(8),
            Constraint::Length(11),
            Constraint::Length(10),
            Constraint::Length(10),
            Constraint::Length(14),
            Constraint::Length(6),
        ],
    )
    .header(
        Row::new(vec![
            "PID", "Name", "CPU", "GPU", "VRAM", "Mem", "Status", "User", "Risk",
        ])
        .style(
            Style::default()
                .fg(Color::Blue)
                .add_modifier(Modifier::BOLD),
        ),
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!("{} Processes", app.processes.len())),
    )
    .row_highlight_style(
        Style::default()
            .fg(Color::Blue)
            .add_modifier(Modifier::REVERSED),
    )
    .highlight_symbol(">> ");

    // Ensure selection is valid
    if app.process_table_state.selected().is_none() && !app.processes.is_empty() {
        app.process_table_state.select(Some(0));
    }

    f.render_stateful_widget(table, body[0], &mut app.process_table_state);

    // Details pane (selected process)
    let details_block = Block::default().borders(Borders::ALL).title("Details");
    let details_area = details_block.inner(body[1]);
    f.render_widget(details_block, body[1]);

    let total_mem_kib = app.collector.get_memory_stats().1.max(1);
    let selected = app.selected_process();
    if let Some(p) = selected {
        let m = p.metrics_history.back().map(|x| &x.1);
        let cpu = m.map(|mm| mm.cpu_usage).unwrap_or(0.0).clamp(0.0, 100.0);
        let gpu_opt = app.gpu_process_usage.get(&p.metadata.pid).copied();

        let vram_opt = app.gpu_process_memory.get(&p.metadata.pid);
        let vram_ded = vram_opt.and_then(|m| m.dedicated_used_mib);
        let vram_sh = vram_opt.and_then(|m| m.shared_used_mib);
        let mem_mib = m.map(|mm| mm.memory_mib()).unwrap_or(0.0);
        let mem_kib = m.map(|mm| mm.memory_usage).unwrap_or(0);
        let mem_pct = ((mem_kib as f64 / total_mem_kib as f64) * 100.0).clamp(0.0, 100.0);
        let virt_mib = m.map(|mm| mm.virtual_memory as f64 / 1024.0).unwrap_or(0.0);
        let disk_r_kib = m.map(|mm| mm.disk_read_kib()).unwrap_or(0);
        let disk_w_kib = m.map(|mm| mm.disk_write_kib()).unwrap_or(0);
        let status = m.map(|mm| mm.status.as_str()).unwrap_or("-");

        let info = vec![
            Line::from(vec![Span::styled(
                &p.metadata.name,
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            )]),
            Line::from(format!(
                "PID: {}    PPID: {}",
                p.metadata.pid,
                p.metadata
                    .parent_pid
                    .map(|x| x.to_string())
                    .unwrap_or("-".into())
            )),
            Line::from(format!(
                "User: {}",
                p.metadata.uid.clone().unwrap_or("-".into())
            )),
            Line::from(format!("Status: {}", status)),
            Line::from(format!(
                "Risk: {:?} ({})",
                p.current_risk.level, p.current_risk.score
            )),
            Line::from(match gpu_opt {
                Some(v) => format!("GPU: {:.1}%", v.clamp(0.0, 100.0)),
                None => "GPU: N/A".to_string(),
            }),
            Line::from(match (vram_ded, vram_sh) {
                (Some(d), Some(s)) => format!("VRAM: {:.0} MiB (shared {:.0} MiB)", d, s),
                (Some(d), None) => format!("VRAM: {:.0} MiB (shared N/A)", d),
                _ => "VRAM: N/A".to_string(),
            }),
            Line::from(""),
            Line::from("Command:"),
            Line::from(p.metadata.command.join(" ")),
            Line::from(""),
            Line::from(format!(
                "Memory: {:.1} MiB (virt {:.1} MiB)",
                mem_mib, virt_mib
            )),
            Line::from(format!(
                "Disk I/O: R {} KiB  W {} KiB",
                disk_r_kib, disk_w_kib
            )),
            Line::from(format!("Start (since boot): {}s", p.metadata.start_time)),
        ];

        // Gauges + details layout
        let gauge_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints(
                [
                    Constraint::Length(3),
                    Constraint::Length(3),
                    Constraint::Min(0),
                ]
                .as_ref(),
            )
            .split(details_area);

        let cpu_g = Gauge::default()
            .block(Block::default().title("CPU").borders(Borders::NONE))
            .gauge_style(Style::default().fg(Color::Cyan))
            .ratio((cpu as f64 / 100.0).clamp(0.0, 1.0))
            .label(format!("{:.1}%", cpu));
        f.render_widget(cpu_g, gauge_chunks[0]);

        let mem_g = Gauge::default()
            .block(Block::default().title("Memory").borders(Borders::NONE))
            .gauge_style(Style::default().fg(Color::LightGreen))
            .ratio((mem_pct / 100.0).clamp(0.0, 1.0))
            .label(format!("{:.1}%", mem_pct));
        f.render_widget(mem_g, gauge_chunks[1]);

        let info_para = Paragraph::new(info)
            .style(Style::default().fg(Color::Gray))
            .wrap(ratatui::widgets::Wrap { trim: true });
        f.render_widget(info_para, gauge_chunks[2]);
    } else {
        let msg = Paragraph::new("No process selected").style(Style::default().fg(Color::Gray));
        f.render_widget(msg, details_area);
    }
}

fn draw_graphs(f: &mut Frame, app: &App, area: Rect) {
    // 3 rows, each row split into 2 columns:
    // 1) CPU usage | CPU frequency
    // 2) RAM usage | GPU speed
    // 3) GPU VRAM | Disk I/O throughput
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(34),
            Constraint::Percentage(33),
            Constraint::Percentage(33),
        ])
        .split(area);

    let row1 = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(rows[0]);
    let row2 = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(rows[1]);
    let row3 = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(rows[2]);

    // CPU usage
    let cpu_last = last_history_value(&app.cpu_history)
        .unwrap_or(0.0)
        .clamp(0.0, 100.0);
    let cpu_points = deque_points(&app.cpu_history);
    let cpu_dataset = vec![Dataset::default()
        .name("CPU Usage (%)")
        .marker(ratatui::symbols::Marker::Braille)
        .style(Style::default().fg(Color::Cyan))
        .graph_type(GraphType::Line)
        .data(&cpu_points)];
    let (cpu_x_min, cpu_x_max) = x_bounds_for_history(&cpu_points);
    let chart_cpu = Chart::new(cpu_dataset)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!("CPU Usage (%)  {:.1}%", cpu_last)),
        )
        .x_axis(Axis::default().title("Time").bounds([cpu_x_min, cpu_x_max]))
        .y_axis(Axis::default().title("%").bounds([0.0, 100.0]));
    f.render_widget(chart_cpu, row1[0]);

    // CPU speed
    let cpu_f_last = last_history_value(&app.cpu_freq_history).unwrap_or(0.0);
    let cpu_freq_points = deque_points(&app.cpu_freq_history);
    let cpu_f_dataset = vec![Dataset::default()
        .name("CPU MHz")
        .marker(ratatui::symbols::Marker::Braille)
        .style(Style::default().fg(Color::Cyan))
        .graph_type(GraphType::Line)
        .data(&cpu_freq_points)];
    let (cpu_f_x_min, cpu_f_x_max) = x_bounds_for_history(&cpu_freq_points);
    let (cpu_f_y_min, cpu_f_y_max) = y_bounds_for_history(&cpu_freq_points, 0.10);
    let chart_cpu_f = Chart::new(cpu_f_dataset)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!("CPU Speed (MHz)  {:.0} MHz", cpu_f_last)),
        )
        .x_axis(
            Axis::default()
                .title("Time")
                .bounds([cpu_f_x_min, cpu_f_x_max]),
        )
        .y_axis(
            Axis::default()
                .title("MHz")
                .bounds([cpu_f_y_min, cpu_f_y_max]),
        );
    f.render_widget(chart_cpu_f, row1[1]);

    // RAM usage
    let ram_last = last_history_value(&app.ram_history)
        .unwrap_or(0.0)
        .clamp(0.0, 100.0);
    let ram_points = deque_points(&app.ram_history);
    let ram_dataset = vec![Dataset::default()
        .name("RAM Usage (%)")
        .marker(ratatui::symbols::Marker::Braille)
        .style(Style::default().fg(Color::LightGreen))
        .graph_type(GraphType::Line)
        .data(&ram_points)];
    let (ram_x_min, ram_x_max) = x_bounds_for_history(&ram_points);
    let chart_ram = Chart::new(ram_dataset)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!("RAM Usage (%)  {:.1}%", ram_last)),
        )
        .x_axis(Axis::default().title("Time").bounds([ram_x_min, ram_x_max]))
        .y_axis(Axis::default().title("%").bounds([0.0, 100.0]));
    f.render_widget(chart_ram, row2[0]);

    // GPU speed (utilization)
    let gpu_last = last_history_value(&app.gpu_history)
        .unwrap_or(0.0)
        .clamp(0.0, 100.0);
    let gpu_points = deque_points(&app.gpu_history);
    let gpu_dataset = vec![Dataset::default()
        .name("GPU Speed (%)")
        .marker(ratatui::symbols::Marker::Braille)
        .style(Style::default().fg(Color::Magenta))
        .graph_type(GraphType::Line)
        .data(&gpu_points)];
    let (gpu_x_min, gpu_x_max) = x_bounds_for_history(&gpu_points);
    let chart_gpu = Chart::new(gpu_dataset)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!("GPU Speed (%)  {:.1}% (Best-effort)", gpu_last)),
        )
        .x_axis(Axis::default().title("Time").bounds([gpu_x_min, gpu_x_max]))
        .y_axis(Axis::default().title("%").bounds([0.0, 100.0]));
    f.render_widget(chart_gpu, row2[1]);

    // GPU VRAM usage (MiB)
    let vram_last = last_history_value(&app.gpu_vram_history)
        .unwrap_or(0.0)
        .max(0.0);
    let vram_total = app
        .gpu_stats
        .as_ref()
        .and_then(|s| s.dedicated_total_mib)
        .unwrap_or(0.0)
        .max(0.0);
    let vram_points = deque_points(&app.gpu_vram_history);
    let vram_dataset = vec![Dataset::default()
        .name("VRAM Used (MiB)")
        .marker(ratatui::symbols::Marker::Braille)
        .style(Style::default().fg(Color::Magenta))
        .graph_type(GraphType::Line)
        .data(&vram_points)];
    let (vram_x_min, vram_x_max) = x_bounds_for_history(&vram_points);
    let (vram_y_min, vram_y_max) = y_bounds_for_history(&vram_points, 0.10);
    let vram_title = if vram_total > 0.0 {
        format!("GPU VRAM (MiB)  {:.0}/{:.0} MiB", vram_last, vram_total)
    } else {
        format!("GPU VRAM (MiB)  {:.0} MiB", vram_last)
    };
    let chart_vram = Chart::new(vram_dataset)
        .block(Block::default().borders(Borders::ALL).title(vram_title))
        .x_axis(
            Axis::default()
                .title("Time")
                .bounds([vram_x_min, vram_x_max]),
        )
        .y_axis(
            Axis::default()
                .title("MiB")
                .bounds([vram_y_min, vram_y_max]),
        );
    f.render_widget(chart_vram, row3[0]);

    // Disk I/O throughput
    let io_r_last = last_history_value(&app.disk_read_mibs_history)
        .unwrap_or(0.0)
        .max(0.0);
    let io_w_last = last_history_value(&app.disk_write_mibs_history)
        .unwrap_or(0.0)
        .max(0.0);
    let io_read_points = deque_points(&app.disk_read_mibs_history);
    let io_write_points = deque_points(&app.disk_write_mibs_history);
    let io_datasets = vec![
        Dataset::default()
            .name("Read MiB/s")
            .marker(ratatui::symbols::Marker::Braille)
            .style(Style::default().fg(Color::Blue))
            .graph_type(GraphType::Line)
            .data(&io_read_points),
        Dataset::default()
            .name("Write MiB/s")
            .marker(ratatui::symbols::Marker::Braille)
            .style(Style::default().fg(Color::Red))
            .graph_type(GraphType::Line)
            .data(&io_write_points),
    ];
    let (io_x_min, io_x_max) = x_bounds_for_history(&io_read_points);
    let (io_y_min, io_y_max) = y_bounds_for_two_histories(&io_read_points, &io_write_points, 0.15);
    let disk_col = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(70), Constraint::Percentage(30)])
        .split(row3[1]);

    let io_title = if app.disk_io_is_best_effort {
        format!(
            "Disk I/O (MiB/s)  R {:.1}  W {:.1} (Best-effort)",
            io_r_last, io_w_last
        )
    } else {
        format!(
            "Disk I/O (MiB/s)  R {:.1}  W {:.1} (PhysicalDisk)",
            io_r_last, io_w_last
        )
    };

    let chart_io = Chart::new(io_datasets)
        .block(Block::default().borders(Borders::ALL).title(io_title))
        .x_axis(Axis::default().title("Time").bounds([io_x_min, io_x_max]))
        .y_axis(Axis::default().title("MiB/s").bounds([io_y_min, io_y_max]));
    f.render_widget(chart_io, disk_col[0]);

    // Per-disk current throughput list
    let mut disk_rates: Vec<(String, f64, f64)> = app
        .disk_io_by_disk
        .iter()
        .filter(|(k, _)| k.as_str() != "_Total")
        .map(|(k, (r, w))| (k.clone(), *r, *w))
        .collect();
    disk_rates.sort_by(|a, b| {
        (b.1 + b.2)
            .partial_cmp(&(a.1 + a.2))
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let mut disk_items: Vec<ListItem> = disk_rates
        .into_iter()
        .take(8)
        .map(|(name, r, w)| {
            ListItem::new(format!("{:<10}  R {:>6.1}  W {:>6.1} MiB/s", name, r, w))
                .style(Style::default().fg(Color::Gray))
        })
        .collect();
    if disk_items.is_empty() {
        disk_items.push(
            ListItem::new("Per-disk rates not available").style(Style::default().fg(Color::Gray)),
        );
    }
    let disk_list = List::new(disk_items).block(
        Block::default()
            .borders(Borders::ALL)
            .title("Disks (Current Throughput)"),
    );
    f.render_widget(disk_list, disk_col[1]);
}

fn last_history_value(data: &VecDeque<(f64, f64)>) -> Option<f64> {
    data.back().map(|p| p.1)
}

fn deque_points(data: &VecDeque<(f64, f64)>) -> Vec<(f64, f64)> {
    data.iter().copied().collect()
}

fn draw_logs(f: &mut Frame, app: &App, area: Rect) {
    let events: Vec<ListItem> = app
        .events
        .iter()
        .rev()
        .take(10)
        .map(|e| {
            let style = match e.severity {
                RiskLevel::Critical => Style::default().fg(Color::Red),
                RiskLevel::High => Style::default().fg(Color::Magenta),
                _ => Style::default(),
            };
            ListItem::new(format!(
                "[{}] {}",
                e.timestamp.format("%H:%M:%S"),
                e.description
            ))
            .style(style)
        })
        .collect();

    let logs = List::new(events).block(Block::default().borders(Borders::ALL).title("Event Log"));
    f.render_widget(logs, area);
}

fn draw_help(f: &mut Frame, area: Rect) {
    let text = vec![
        Line::from(Span::styled(
            "═══ Intelligent Process Monitor ═══",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "⌨  Navigation:",
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from("  Tab          - Switch between tabs"),
        Line::from("  D / P / G / H - Jump to Dashboard / Processes / Graphs / Help"),
        Line::from("  Up/Down      - Scroll process list (in Processes tab)"),
        Line::from("  q / Esc      - Quit application"),
        Line::from("  Ctrl+C       - Quit application"),
        Line::from(""),
        Line::from(Span::styled(
            "Processes tab:",
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from("  s            - Cycle sort column"),
        Line::from("  r            - Reverse sort direction"),
        Line::from(""),
        Line::from(Span::styled(
            "Features:",
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from("  • Dashboard  - System overview with CPU/RAM/GPU charts"),
        Line::from("  • Processes  - Detailed process list with metrics"),
        Line::from("  • Graphs     - Real-time CPU, RAM and GPU usage charts"),
        Line::from("  • Events     - Live process monitoring and risk alerts"),
        Line::from(""),
        Line::from(Span::styled(
            "Risk Levels:",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(vec![
            Span::styled("  Low      ", Style::default().fg(Color::Green)),
            Span::raw("- Normal operation"),
        ]),
        Line::from(vec![
            Span::styled("  Medium   ", Style::default().fg(Color::Yellow)),
            Span::raw("- Moderate resource usage"),
        ]),
        Line::from(vec![
            Span::styled("  High     ", Style::default().fg(Color::Magenta)),
            Span::raw("- High resource consumption"),
        ]),
        Line::from(vec![
            Span::styled("  Critical ", Style::default().fg(Color::Red)),
            Span::raw("- Potential security concern"),
        ]),
    ];
    let p = Paragraph::new(text).block(
        Block::default()
            .borders(Borders::ALL)
            .title("Help & Information"),
    );
    f.render_widget(p, area);
}

fn x_bounds_for_history(data: &[(f64, f64)]) -> (f64, f64) {
    if data.is_empty() {
        return (0.0, 1.0);
    }
    let x_min = data.first().map(|p| p.0).unwrap_or(0.0);
    let mut x_max = data.last().map(|p| p.0).unwrap_or(x_min + 1.0);
    if x_max <= x_min {
        x_max = x_min + 1.0;
    }
    (x_min, x_max)
}

fn y_bounds_for_history(data: &[(f64, f64)], pad_ratio: f64) -> (f64, f64) {
    if data.is_empty() {
        return (0.0, 1.0);
    }
    let mut min_v = f64::INFINITY;
    let mut max_v = f64::NEG_INFINITY;
    for (_, v) in data {
        if v.is_finite() {
            min_v = min_v.min(*v);
            max_v = max_v.max(*v);
        }
    }

    if !min_v.is_finite() || !max_v.is_finite() {
        return (0.0, 1.0);
    }

    if (max_v - min_v).abs() < f64::EPSILON {
        // Flat line: give it a visible band.
        let base = max_v;
        return ((base - 1.0).max(0.0), base + 1.0);
    }

    let pad = (max_v - min_v) * pad_ratio.clamp(0.0, 1.0);
    let y_min = (min_v - pad).max(0.0);
    let y_max = max_v + pad;
    if y_max <= y_min {
        (y_min, y_min + 1.0)
    } else {
        (y_min, y_max)
    }
}

fn y_bounds_for_two_histories(a: &[(f64, f64)], b: &[(f64, f64)], pad_ratio: f64) -> (f64, f64) {
    let mut merged: Vec<(f64, f64)> = Vec::with_capacity(a.len() + b.len());
    merged.extend_from_slice(a);
    merged.extend_from_slice(b);
    y_bounds_for_history(&merged, pad_ratio)
}

fn draw_mini_chart(
    f: &mut Frame,
    data: &VecDeque<(f64, f64)>,
    area: Rect,
    title: &str,
    color: Color,
) {
    if data.is_empty() {
        let msg = Paragraph::new("Waiting for data...")
            .block(Block::default().borders(Borders::ALL).title(title))
            .style(Style::default().fg(Color::Gray));
        f.render_widget(msg, area);
        return;
    }

    let points = deque_points(data);
    let datasets = vec![Dataset::default()
        .name("Usage")
        .marker(ratatui::symbols::Marker::Dot)
        .style(Style::default().fg(color))
        .data(&points)];

    let (x_min, x_max) = x_bounds_for_history(&points);
    let chart = Chart::new(datasets)
        .block(Block::default().borders(Borders::ALL).title(title))
        .x_axis(Axis::default().bounds([x_min, x_max]))
        .y_axis(Axis::default().bounds([0.0, 100.0]));

    f.render_widget(chart, area);
}
