use crate::analyzer::BehaviorAnalyzer;
use crate::collector::SystemCollector;
use crate::gpu::{GpuAdapterInfo, GpuProcessMemory, GpuStats};
use crate::logger::EventLogger;
use crate::models::{EventType, MonitoredProcess, RiskLevel, SystemEvent};
use chrono::DateTime;
use chrono::Utc;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::widgets::TableState;
use std::cmp::Reverse;
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortBy {
    Cpu,
    Memory,
    Name,
    Pid,
    Risk,
}

pub struct App {
    pub selected_tab: usize,
    pub should_quit: bool,
    pub collector: SystemCollector,
    pub analyzer: BehaviorAnalyzer,
    pub processes: Vec<MonitoredProcess>,
    pub events: VecDeque<SystemEvent>,
    pub cpu_history: VecDeque<(f64, f64)>, // (time_index, value)
    pub ram_history: VecDeque<(f64, f64)>,
    pub gpu_history: VecDeque<(f64, f64)>,
    pub gpu_vram_history: VecDeque<(f64, f64)>,
    pub cpu_freq_history: VecDeque<(f64, f64)>,
    pub ram_speed_history: VecDeque<(f64, f64)>,
    pub disk_read_mibs_history: VecDeque<(f64, f64)>,
    pub disk_write_mibs_history: VecDeque<(f64, f64)>,
    pub disk_io_by_disk: HashMap<String, (f64, f64)>,
    pub disk_io_is_best_effort: bool,
    pub uptime: u64,
    pub tick_count: f64,
    pub last_refresh: DateTime<Utc>,
    pub last_tick_instant: Instant,
    pub gpu_adapters: Vec<GpuAdapterInfo>,
    pub last_gpu_refresh: DateTime<Utc>,
    pub gpu_stats: Option<GpuStats>,
    pub last_gpu_stats_refresh: DateTime<Utc>,
    pub gpu_process_usage: HashMap<u32, f64>,
    pub last_gpu_proc_refresh: DateTime<Utc>,
    pub gpu_process_memory: HashMap<u32, GpuProcessMemory>,
    pub last_gpu_mem_refresh: DateTime<Utc>,
    pub cpu_freq_mhz: Option<u64>,
    pub ram_speed_mhz: Option<u64>,
    pub last_hw_stats_refresh: DateTime<Utc>,
    pub last_total_disk_read: Option<u64>,
    pub last_total_disk_write: Option<u64>,
    pub os_info: String,
    pub host_name: String,
    pub disk_usage_text: String,
    pub startup_diagnostics: Vec<String>,
    pub known_pids: HashSet<u32>,
    pub process_table_state: TableState,
    pub selected_pid: Option<u32>,
    pub sort_by: SortBy,
    pub sort_desc: bool,
}

impl App {
    pub fn new() -> Self {
        let mut collector = SystemCollector::new();

        // Initial refresh to populate CPU data (sysinfo needs 2 measurements for CPU%)
        collector.refresh();
        std::thread::sleep(std::time::Duration::from_millis(200));
        collector.refresh();

        let os_info = collector.get_os_info();
        let host_name = collector.get_host_name();
        let disk_usage_text = collector.get_disk_space_summary();
        let gpu_adapters = crate::gpu::enumerate_adapters();
        let last_gpu_refresh = Utc::now();
        let gpu_stats = crate::gpu::read_gpu_stats();
        let last_gpu_stats_refresh = Utc::now();
        let gpu_process_usage = crate::gpu::read_gpu_process_usage();
        let last_gpu_proc_refresh = Utc::now();
        let gpu_process_memory = crate::gpu::read_gpu_process_memory();
        let last_gpu_mem_refresh = Utc::now();
        let cpu_freq_mhz = collector.get_avg_cpu_frequency_mhz();
        let ram_speed_mhz = collector.get_ram_speed_mhz();
        let startup_diagnostics = build_startup_diagnostics(
            &gpu_adapters,
            &gpu_stats,
            &gpu_process_usage,
            &gpu_process_memory,
            cpu_freq_mhz,
            ram_speed_mhz,
        );
        let last_hw_stats_refresh = Utc::now();
        let mut process_table_state = TableState::default();
        process_table_state.select(Some(0));

        // Seed a small history so charts are never completely empty at startup.
        let cpu_now = collector.get_global_cpu_usage() as f64;
        let (used_mem, total_mem) = collector.get_memory_stats();
        let mem_percent = if total_mem > 0 {
            (used_mem as f64 / total_mem as f64) * 100.0
        } else {
            0.0
        };
        let gpu_now = gpu_stats
            .as_ref()
            .and_then(|s| s.utilization_percent)
            .unwrap_or(0.0)
            .clamp(0.0, 100.0);
        let gpu_vram_now = gpu_stats
            .as_ref()
            .and_then(|s| s.dedicated_used_mib)
            .unwrap_or(0.0)
            .max(0.0);

        let mut cpu_history = VecDeque::with_capacity(101);
        let mut ram_history = VecDeque::with_capacity(101);
        let mut gpu_history = VecDeque::with_capacity(101);
        let mut gpu_vram_history = VecDeque::with_capacity(101);
        let mut cpu_freq_history = VecDeque::with_capacity(101);
        let mut ram_speed_history = VecDeque::with_capacity(101);
        let mut disk_read_mibs_history = VecDeque::with_capacity(101);
        let mut disk_write_mibs_history = VecDeque::with_capacity(101);
        for i in 0..10 {
            cpu_history.push_back((i as f64, cpu_now));
            ram_history.push_back((i as f64, mem_percent));
            gpu_history.push_back((i as f64, gpu_now));
            gpu_vram_history.push_back((i as f64, gpu_vram_now));
            cpu_freq_history.push_back((i as f64, cpu_freq_mhz.unwrap_or(0) as f64));
            ram_speed_history.push_back((i as f64, ram_speed_mhz.unwrap_or(0) as f64));
            disk_read_mibs_history.push_back((i as f64, 0.0));
            disk_write_mibs_history.push_back((i as f64, 0.0));
        }

        Self {
            selected_tab: 0,
            should_quit: false,
            collector,
            analyzer: BehaviorAnalyzer::new(),
            processes: Vec::new(),
            events: VecDeque::new(),
            cpu_history,
            ram_history,
            gpu_history,
            gpu_vram_history,
            cpu_freq_history,
            ram_speed_history,
            disk_read_mibs_history,
            disk_write_mibs_history,
            disk_io_by_disk: HashMap::new(),
            disk_io_is_best_effort: true,
            uptime: 0,
            tick_count: 9.0,
            last_refresh: Utc::now(),
            last_tick_instant: Instant::now(),
            gpu_adapters,
            last_gpu_refresh,
            gpu_stats,
            last_gpu_stats_refresh,
            gpu_process_usage,
            last_gpu_proc_refresh,
            gpu_process_memory,
            last_gpu_mem_refresh,
            cpu_freq_mhz,
            ram_speed_mhz,
            last_hw_stats_refresh,
            last_total_disk_read: None,
            last_total_disk_write: None,
            os_info,
            host_name,
            disk_usage_text,
            startup_diagnostics,
            known_pids: HashSet::new(),
            process_table_state,
            selected_pid: None,
            sort_by: SortBy::Cpu,
            sort_desc: true,
        }
    }

    pub fn selected_process(&self) -> Option<&MonitoredProcess> {
        let idx = self.process_table_state.selected()?;
        self.processes.get(idx)
    }

    fn cycle_sort(&mut self) {
        self.sort_by = match self.sort_by {
            SortBy::Cpu => SortBy::Memory,
            SortBy::Memory => SortBy::Name,
            SortBy::Name => SortBy::Pid,
            SortBy::Pid => SortBy::Risk,
            SortBy::Risk => SortBy::Cpu,
        };
    }

    pub fn next_process(&mut self) {
        if self.processes.is_empty() {
            self.process_table_state.select(None);
            self.selected_pid = None;
            return;
        }
        let i = match self.process_table_state.selected() {
            Some(i) => {
                if i >= self.processes.len() - 1 {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.process_table_state.select(Some(i));
        self.selected_pid = self.processes.get(i).map(|p| p.metadata.pid);
    }

    pub fn previous_process(&mut self) {
        if self.processes.is_empty() {
            self.process_table_state.select(None);
            self.selected_pid = None;
            return;
        }
        let i = match self.process_table_state.selected() {
            Some(i) => {
                if i == 0 {
                    self.processes.len() - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.process_table_state.select(Some(i));
        self.selected_pid = self.processes.get(i).map(|p| p.metadata.pid);
    }

    pub fn on_tick(&mut self) {
        let tick_elapsed = self.last_tick_instant.elapsed();
        self.last_tick_instant = Instant::now();
        let tick_secs = (tick_elapsed.as_secs_f64()).max(0.25); // avoid spikes on stalls

        self.tick_count += 1.0;
        let now = Utc::now();
        self.last_refresh = now;

        // Remember selection by PID so sorting/refresh doesn't "jump" the cursor.
        if self.selected_pid.is_none() {
            self.selected_pid = self.selected_process().map(|p| p.metadata.pid);
        }

        self.collector.refresh();
        let collected = self.collector.collect_processes();
        self.uptime = self.collector.get_system_uptime();
        // Keep disk info “live” too (collector throttles expensive disk list refresh internally).
        self.disk_usage_text = self.collector.get_disk_space_summary();

        // Disk throughput.
        // - Windows: prefer true PhysicalDisk perf counters (MiB/s) per disk.
        // - Others: best-effort by summing per-process cumulative counters.
        let (read_mibs, write_mibs) = {
            #[cfg(windows)]
            {
                let by_disk = self.collector.get_physical_disk_throughput_mibs();
                if !by_disk.is_empty() {
                    self.disk_io_by_disk = by_disk;
                    self.disk_io_is_best_effort = false;
                    self.disk_io_by_disk
                        .get("_Total")
                        .copied()
                        .unwrap_or_else(|| {
                            self.disk_io_by_disk
                                .iter()
                                .filter(|(k, _)| k.as_str() != "_Total")
                                .fold((0.0, 0.0), |acc, (_, v)| (acc.0 + v.0, acc.1 + v.1))
                        })
                } else {
                    // Fall back to best-effort when perf class isn't available.
                    self.disk_io_is_best_effort = true;

                    let total_read: u64 = collected.iter().map(|(_, _, m)| m.disk_read).sum();
                    let total_write: u64 = collected.iter().map(|(_, _, m)| m.disk_write).sum();

                    let delta_read = self
                        .last_total_disk_read
                        .map(|prev| total_read.saturating_sub(prev))
                        .unwrap_or(0);
                    let delta_write = self
                        .last_total_disk_write
                        .map(|prev| total_write.saturating_sub(prev))
                        .unwrap_or(0);

                    self.last_total_disk_read = Some(total_read);
                    self.last_total_disk_write = Some(total_write);

                    (
                        (delta_read as f64 / 1_048_576.0) / tick_secs,
                        (delta_write as f64 / 1_048_576.0) / tick_secs,
                    )
                }
            }

            #[cfg(not(windows))]
            {
                self.disk_io_is_best_effort = true;

                let total_read: u64 = collected.iter().map(|(_, _, m)| m.disk_read).sum();
                let total_write: u64 = collected.iter().map(|(_, _, m)| m.disk_write).sum();

                let delta_read = self
                    .last_total_disk_read
                    .map(|prev| total_read.saturating_sub(prev))
                    .unwrap_or(0);
                let delta_write = self
                    .last_total_disk_write
                    .map(|prev| total_write.saturating_sub(prev))
                    .unwrap_or(0);

                self.last_total_disk_read = Some(total_read);
                self.last_total_disk_write = Some(total_write);

                (
                    (delta_read as f64 / 1_048_576.0) / tick_secs,
                    (delta_write as f64 / 1_048_576.0) / tick_secs,
                )
            }
        };

        push_history_capped(
            &mut self.disk_read_mibs_history,
            (self.tick_count, read_mibs),
            100,
        );
        push_history_capped(
            &mut self.disk_write_mibs_history,
            (self.tick_count, write_mibs),
            100,
        );

        // Refresh GPU adapter list occasionally (adapter enumeration can be expensive on some systems).
        if (Utc::now() - self.last_gpu_refresh).num_seconds() >= 10 {
            self.gpu_adapters = crate::gpu::enumerate_adapters();
            self.last_gpu_refresh = Utc::now();
        }

        // Refresh GPU stats (utilization + memory) every tick (tick-rate is 1s by default).
        if (Utc::now() - self.last_gpu_stats_refresh).num_seconds() >= 1 {
            self.gpu_stats = crate::gpu::read_gpu_stats();
            self.last_gpu_stats_refresh = Utc::now();
        }

        // Refresh per-process GPU usage (WMI can be heavy on some systems).
        if (Utc::now() - self.last_gpu_proc_refresh).num_seconds() >= 2 {
            self.gpu_process_usage = crate::gpu::read_gpu_process_usage();
            self.last_gpu_proc_refresh = Utc::now();
        }

        // Refresh per-process GPU memory usage (WMI can be heavy on some systems).
        if (Utc::now() - self.last_gpu_mem_refresh).num_seconds() >= 2 {
            self.gpu_process_memory = crate::gpu::read_gpu_process_memory();
            self.last_gpu_mem_refresh = Utc::now();
        }

        // Refresh CPU frequency every tick (cheap; comes from sysinfo).
        self.cpu_freq_mhz = self.collector.get_avg_cpu_frequency_mhz();

        // RAM speed is usually constant (hardware clock), and WMI can be expensive.
        // We refresh it occasionally and also retry if we don't have it yet.
        if self.ram_speed_mhz.is_none()
            || (Utc::now() - self.last_hw_stats_refresh).num_seconds() >= 10
        {
            self.ram_speed_mhz = self.collector.get_ram_speed_mhz().or(self.ram_speed_mhz);
            self.last_hw_stats_refresh = Utc::now();
        }

        // 1. Detect New Processes
        let mut current_pids: HashSet<u32> =
            HashSet::with_capacity(collected.len().saturating_mul(2));
        current_pids.extend(collected.iter().map(|(pid, _, _)| *pid));

        // Initial population (first tick)
        if self.known_pids.is_empty() {
            self.known_pids = current_pids.clone();
        } else {
            // Find diff
            for (pid, metadata, _) in &collected {
                if !self.known_pids.contains(pid) {
                    // New Process!
                    let event = SystemEvent {
                        timestamp: Utc::now(),
                        event_type: EventType::ProcessStarted,
                        pid: *pid,
                        description: format!("Started: {} ({})", metadata.name, pid),
                        severity: RiskLevel::Low,
                    };
                    EventLogger::log_event(&event);
                    self.events.push_back(event);

                    // Keep events list manageable (max 100 events)
                    if self.events.len() > 100 {
                        self.events.pop_front();
                    }
                }
            }

            // Track dead processes (Optional, but good for "Live" feel)
            // for old_pid in &self.known_pids {
            //    if !current_pids.contains(old_pid) { ... }
            // }

            self.known_pids = current_pids;
        }

        // Persist per-PID history: move existing processes into a PID map, then rebuild the list
        // for the currently running PIDs. This avoids cloning large histories each tick.
        let mut existing_by_pid: HashMap<u32, MonitoredProcess> =
            HashMap::with_capacity(self.processes.len().saturating_mul(2));
        for p in self.processes.drain(..) {
            existing_by_pid.insert(p.metadata.pid, p);
        }
        let mut new_processes: Vec<MonitoredProcess> = Vec::with_capacity(collected.len());

        for (pid, metadata, metrics) in collected.into_iter() {
            let (mut proc, is_high_risk) = match existing_by_pid.remove(&pid) {
                Some(mut p) => {
                    // Keep metadata fresh (name/cmd can change for some process handles).
                    p.metadata = metadata;
                    let risk = self.analyzer.analyze_process(&p.metadata, &metrics);
                    let is_high = matches!(risk.level, RiskLevel::High | RiskLevel::Critical);
                    p.current_risk = risk;
                    (p, is_high)
                }
                None => {
                    let risk = self.analyzer.analyze_process(&metadata, &metrics);
                    let is_high = matches!(risk.level, RiskLevel::High | RiskLevel::Critical);
                    (
                        MonitoredProcess {
                            metadata,
                            metrics_history: VecDeque::new(),
                            current_risk: risk,
                            lineage_path: vec![],
                        },
                        is_high,
                    )
                }
            };

            // Append history and cap to keep memory bounded.
            proc.metrics_history.push_back((now, metrics));
            const MAX_METRICS_HISTORY: usize = 60;
            if proc.metrics_history.len() > MAX_METRICS_HISTORY {
                while proc.metrics_history.len() > MAX_METRICS_HISTORY {
                    proc.metrics_history.pop_front();
                }
            }

            // Optionally log events.
            if is_high_risk {
                let last_anomaly =
                    self.events.iter().rev().take(20).find(|e| {
                        e.pid == pid && matches!(e.event_type, EventType::AnomalyDetected)
                    });
                let should_log = match last_anomaly {
                    None => true,
                    Some(e) => (now - e.timestamp).num_seconds() >= 10,
                };

                if should_log {
                    let event = SystemEvent {
                        timestamp: now,
                        event_type: EventType::AnomalyDetected,
                        pid,
                        description: format!(
                            "Risk: {} [{:?}] - {}",
                            proc.metadata.name,
                            proc.current_risk.level,
                            proc.current_risk
                                .factors
                                .first()
                                .map(|s| s.as_str())
                                .unwrap_or("")
                        ),
                        severity: proc.current_risk.level.clone(),
                    };
                    EventLogger::log_event(&event);
                    self.events.push_back(event);
                    if self.events.len() > 100 {
                        self.events.pop_front();
                    }
                }
            }

            new_processes.push(proc);
        }

        self.processes = new_processes;

        // Sort (Task Manager style) and keep PID tie-breakers stable.
        match self.sort_by {
            SortBy::Cpu => {
                let desc = self.sort_desc;
                self.processes.sort_by(|a, b| {
                    let av = a
                        .metrics_history
                        .back()
                        .map(|x| x.1.cpu_usage)
                        .unwrap_or(0.0);
                    let bv = b
                        .metrics_history
                        .back()
                        .map(|x| x.1.cpu_usage)
                        .unwrap_or(0.0);

                    let mut ord = av.partial_cmp(&bv).unwrap_or(std::cmp::Ordering::Equal);
                    if desc {
                        ord = ord.reverse();
                    }
                    ord.then_with(|| a.metadata.pid.cmp(&b.metadata.pid))
                });
            }
            SortBy::Memory => {
                if self.sort_desc {
                    self.processes.sort_by_key(|p| {
                        let mem = p
                            .metrics_history
                            .back()
                            .map(|x| x.1.memory_usage)
                            .unwrap_or(0);
                        (Reverse(mem), p.metadata.pid)
                    });
                } else {
                    self.processes.sort_by_key(|p| {
                        let mem = p
                            .metrics_history
                            .back()
                            .map(|x| x.1.memory_usage)
                            .unwrap_or(0);
                        (mem, p.metadata.pid)
                    });
                }
            }
            SortBy::Name => {
                if self.sort_desc {
                    self.processes.sort_by_cached_key(|p| {
                        (Reverse(p.metadata.name.to_lowercase()), p.metadata.pid)
                    });
                } else {
                    self.processes
                        .sort_by_cached_key(|p| (p.metadata.name.to_lowercase(), p.metadata.pid));
                }
            }
            SortBy::Pid => {
                if self.sort_desc {
                    self.processes.sort_by_key(|p| Reverse(p.metadata.pid));
                } else {
                    self.processes.sort_by_key(|p| p.metadata.pid);
                }
            }
            SortBy::Risk => {
                if self.sort_desc {
                    self.processes
                        .sort_by_key(|p| (Reverse(p.current_risk.score), p.metadata.pid));
                } else {
                    self.processes
                        .sort_by_key(|p| (p.current_risk.score, p.metadata.pid));
                }
            }
        }

        // Restore selection
        if let Some(pid) = self.selected_pid {
            if let Some(idx) = self.processes.iter().position(|p| p.metadata.pid == pid) {
                self.process_table_state.select(Some(idx));
            }
        }

        // Ensure selection stays within bounds if list shrinks
        if let Some(selected) = self.process_table_state.selected() {
            if selected >= self.processes.len() {
                self.process_table_state
                    .select(Some(self.processes.len().saturating_sub(1)));
            }
        }

        // If we still have no PID selected, pick the current row.
        if self.selected_pid.is_none() {
            self.selected_pid = self.selected_process().map(|p| p.metadata.pid);
        }

        // Update Chart Data with EXACT Global CPU Usage
        let global_cpu = self.collector.get_global_cpu_usage();

        push_history_capped(
            &mut self.cpu_history,
            (self.tick_count, global_cpu as f64),
            100,
        );

        // Convert to f64 for calculations
        let (used_mem, total_mem) = self.collector.get_memory_stats();
        let mem_percent = if total_mem > 0 {
            (used_mem as f64 / total_mem as f64) * 100.0
        } else {
            0.0
        };

        push_history_capped(&mut self.ram_history, (self.tick_count, mem_percent), 100);

        // CPU frequency history (MHz)
        let cpu_mhz = self.cpu_freq_mhz.unwrap_or(0) as f64;
        push_history_capped(&mut self.cpu_freq_history, (self.tick_count, cpu_mhz), 100);

        // RAM speed history (MHz) - mostly constant
        let ram_mhz = self.ram_speed_mhz.unwrap_or(0) as f64;
        push_history_capped(&mut self.ram_speed_history, (self.tick_count, ram_mhz), 100);

        // GPU history (best-effort). Keep it aligned with tick_count.
        let gpu_percent = self
            .gpu_stats
            .as_ref()
            .and_then(|s| s.utilization_percent)
            .unwrap_or(0.0)
            .clamp(0.0, 100.0);
        push_history_capped(&mut self.gpu_history, (self.tick_count, gpu_percent), 100);

        // GPU VRAM usage history (MiB) - best effort.
        let gpu_vram_used = self
            .gpu_stats
            .as_ref()
            .and_then(|s| s.dedicated_used_mib)
            .unwrap_or(0.0)
            .max(0.0);
        push_history_capped(
            &mut self.gpu_vram_history,
            (self.tick_count, gpu_vram_used),
            100,
        );
    }

    pub fn on_key(&mut self, key: KeyEvent) {
        // Quit should always work, regardless of active tab.
        if matches!(key.code, KeyCode::Esc)
            || (matches!(key.code, KeyCode::Char('c'))
                && key.modifiers.contains(KeyModifiers::CONTROL))
            || matches!(key.code, KeyCode::Char('q') | KeyCode::Char('Q'))
        {
            self.should_quit = true;
            return;
        }

        match key.code {
            KeyCode::Tab | KeyCode::Char('\t') => self.selected_tab = (self.selected_tab + 1) % 4,
            KeyCode::BackTab => self.selected_tab = (self.selected_tab + 3) % 4,
            KeyCode::Char('1') => self.selected_tab = 0,
            KeyCode::Char('2') => self.selected_tab = 1,
            KeyCode::Char('3') => self.selected_tab = 2,
            KeyCode::Char('4') => self.selected_tab = 3,
            // Direct tab hotkeys
            KeyCode::Char('d') | KeyCode::Char('D') => self.selected_tab = 0,
            KeyCode::Char('p') | KeyCode::Char('P') => self.selected_tab = 1,
            KeyCode::Char('g') | KeyCode::Char('G') => self.selected_tab = 2,
            KeyCode::Char('h') | KeyCode::Char('H') => self.selected_tab = 3,
            KeyCode::Down => {
                if self.selected_tab == 1 {
                    // Processes Tab
                    self.next_process();
                }
            }
            KeyCode::Up => {
                if self.selected_tab == 1 {
                    // Processes Tab
                    self.previous_process();
                }
            }
            KeyCode::Char('s') => {
                if self.selected_tab == 1 {
                    self.cycle_sort();
                }
            }
            KeyCode::Char('r') => {
                if self.selected_tab == 1 {
                    self.sort_desc = !self.sort_desc;
                }
            }
            _ => {}
        }
    }
}

fn build_startup_diagnostics(
    gpu_adapters: &[GpuAdapterInfo],
    gpu_stats: &Option<GpuStats>,
    gpu_process_usage: &HashMap<u32, f64>,
    gpu_process_memory: &HashMap<u32, GpuProcessMemory>,
    cpu_freq_mhz: Option<u64>,
    ram_speed_mhz: Option<u64>,
) -> Vec<String> {
    let mut lines = Vec::with_capacity(8);

    lines.push("Core metrics provider: sysinfo (active)".to_string());

    #[cfg(windows)]
    lines.push("CPU/RAM extra provider: WMI (best-effort)".to_string());
    #[cfg(target_os = "linux")]
    lines.push("CPU/RAM extra provider: cpufreq + dmidecode (best-effort)".to_string());
    #[cfg(target_os = "macos")]
    lines.push("CPU/RAM extra provider: sysinfo + system_profiler (best-effort)".to_string());

    #[cfg(windows)]
    lines.push("Disk throughput provider: PhysicalDisk WMI or process delta fallback".to_string());
    #[cfg(not(windows))]
    lines.push("Disk throughput provider: process delta fallback".to_string());

    lines.push(if gpu_adapters.is_empty() {
        "GPU adapter provider: wgpu (no adapters detected)".to_string()
    } else {
        "GPU adapter provider: wgpu (active)".to_string()
    });

    lines.push(if gpu_stats.is_some() {
        "GPU global metrics provider: platform API (active)".to_string()
    } else {
        "GPU global metrics provider: unavailable on this host".to_string()
    });

    lines.push(if gpu_process_usage.is_empty() {
        "GPU process usage provider: unavailable".to_string()
    } else {
        "GPU process usage provider: active".to_string()
    });

    lines.push(if gpu_process_memory.is_empty() {
        "GPU process memory provider: unavailable".to_string()
    } else {
        "GPU process memory provider: active".to_string()
    });

    lines.push(if cpu_freq_mhz.is_some() {
        "CPU frequency metric: active".to_string()
    } else {
        "CPU frequency metric: unavailable".to_string()
    });

    lines.push(if ram_speed_mhz.is_some() {
        "RAM speed metric: active".to_string()
    } else {
        "RAM speed metric: unavailable".to_string()
    });

    #[cfg(feature = "nvidia-nvml")]
    lines.push("NVIDIA NVML feature: enabled".to_string());
    #[cfg(not(feature = "nvidia-nvml"))]
    lines.push("NVIDIA NVML feature: disabled".to_string());

    lines
}

#[inline]
fn push_history_capped(buf: &mut VecDeque<(f64, f64)>, point: (f64, f64), cap: usize) {
    if buf.len() >= cap {
        buf.pop_front();
    }
    buf.push_back(point);
}
