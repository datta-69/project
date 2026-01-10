use crate::models::{ProcessMetadata, ProcessMetrics};
use sysinfo::{CpuRefreshKind, Disks, MemoryRefreshKind, ProcessRefreshKind, RefreshKind, System};

#[cfg(target_os = "linux")]
use std::{fs, path::Path, process::Command};

#[cfg(windows)]
use serde::Deserialize;

#[cfg(windows)]
use wmi::{COMLibrary, WMIConnection};

pub struct SystemCollector {
    sys: System,
    disks: Disks,
    last_disk_refresh: std::time::Instant,

    #[cfg(windows)]
    last_cpu_freq_refresh: std::time::Instant,
    #[cfg(windows)]
    cached_cpu_freq_mhz: Option<u64>,

    #[cfg(windows)]
    wmi_con: Option<WMIConnection>,

    #[cfg(target_os = "linux")]
    linux_ram_speed_attempted: bool,
    #[cfg(target_os = "linux")]
    cached_ram_speed_mhz: Option<u64>,
}

impl Default for SystemCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl SystemCollector {
    pub fn new() -> Self {
        let sys = System::new_with_specifics(
            RefreshKind::new()
                .with_processes(ProcessRefreshKind::everything())
                .with_memory(MemoryRefreshKind::everything())
                .with_cpu(CpuRefreshKind::everything()),
        );
        let disks = Disks::new_with_refreshed_list();

        Self {
            sys,
            disks,
            last_disk_refresh: std::time::Instant::now(),

            #[cfg(windows)]
            last_cpu_freq_refresh: std::time::Instant::now(),
            #[cfg(windows)]
            cached_cpu_freq_mhz: None,

            #[cfg(windows)]
            wmi_con: None,

            #[cfg(target_os = "linux")]
            linux_ram_speed_attempted: false,
            #[cfg(target_os = "linux")]
            cached_ram_speed_mhz: None,
        }
    }

    #[cfg(windows)]
    fn ensure_wmi(&mut self) -> Option<&WMIConnection> {
        if self.wmi_con.is_none() {
            let com_con = COMLibrary::new().ok()?;
            let wmi_con = WMIConnection::new(com_con).ok()?;
            self.wmi_con = Some(wmi_con);
        }
        self.wmi_con.as_ref()
    }

    pub fn refresh(&mut self) {
        self.sys.refresh_processes();
        self.sys.refresh_memory();
        self.sys.refresh_cpu();

        // Refresh disk usage stats (cheap) each tick.
        self.disks.refresh();

        // Only refresh disk list every 60 seconds (expensive operation)
        if self.last_disk_refresh.elapsed().as_secs() > 60 {
            self.disks.refresh_list();
            self.last_disk_refresh = std::time::Instant::now();
        }
    }

    pub fn get_os_info(&self) -> String {
        let name = System::name().unwrap_or("Unknown".to_string());
        let version = System::os_version().unwrap_or("".to_string());
        format!("{} {}", name, version)
    }

    pub fn get_host_name(&self) -> String {
        System::host_name().unwrap_or("Unknown".to_string())
    }

    pub fn get_global_cpu_usage(&self) -> f32 {
        self.sys.global_cpu_info().cpu_usage()
    }

    /// Best-effort average CPU frequency in MHz.
    ///
    /// Notes:
    /// - On Windows, `sysinfo` often reports the base frequency (static). We prefer a perf-counter
    ///   value via WMI when available, which updates live with boost/power states.
    pub fn get_avg_cpu_frequency_mhz(&mut self) -> Option<u64> {
        #[cfg(windows)]
        {
            // Avoid hammering WMI every tick; CPU MHz changes relatively slowly anyway.
            if self.last_cpu_freq_refresh.elapsed() < std::time::Duration::from_millis(500)
                && self.cached_cpu_freq_mhz.is_some()
            {
                return self.cached_cpu_freq_mhz;
            }

            #[allow(non_snake_case)]
            #[derive(Debug, Deserialize)]
            struct Win32ProcessorInformation {
                Name: String,
                ProcessorFrequency: Option<u32>,
                ActualFrequency: Option<u32>,
                PercentofMaximumFrequency: Option<u32>,
            }

            // Prefer live perf counter: Win32_PerfFormattedData_Counters_ProcessorInformation
            // If it fails (missing class/permissions), fall back to sysinfo.
            let wmi_value: Option<u64> = (|| {
                let wmi_con = self.ensure_wmi()?;
                let rows: Vec<Win32ProcessorInformation> = wmi_con
                    .raw_query(
                        "SELECT Name, ProcessorFrequency, ActualFrequency, PercentofMaximumFrequency FROM Win32_PerfFormattedData_Counters_ProcessorInformation",
                    )
                    .ok()?;

                // Task Manager's “Speed” aligns best with the perf counter "ActualFrequency".
                // Fall back to a derived effective MHz using base * % of max, and lastly base.
                let pick_mhz = |r: &Win32ProcessorInformation| -> Option<u64> {
                    if let Some(v) = r.ActualFrequency {
                        let v = v as u64;
                        if v > 0 {
                            return Some(v);
                        }
                    }
                    if let (Some(base), Some(pct)) = (
                        r.ProcessorFrequency.map(|v| v as u64),
                        r.PercentofMaximumFrequency,
                    ) {
                        let pct = pct as u64;
                        if base > 0 && pct > 0 {
                            return Some((base.saturating_mul(pct) + 50) / 100);
                        }
                    }
                    r.ProcessorFrequency.map(|v| v as u64).filter(|v| *v > 0)
                };

                let total = rows
                    .iter()
                    .find(|r| r.Name.contains("_Total"))
                    .and_then(pick_mhz);
                if total.is_some() {
                    return total;
                }

                let freqs: Vec<u64> = rows
                    .into_iter()
                    .filter_map(|r| pick_mhz(&r))
                    .filter(|v| *v > 0)
                    .collect();
                if freqs.is_empty() {
                    return None;
                }
                let sum: u64 = freqs.iter().sum();
                Some(sum / freqs.len() as u64)
            })();

            self.last_cpu_freq_refresh = std::time::Instant::now();
            if wmi_value.is_some() {
                self.cached_cpu_freq_mhz = wmi_value;
                return wmi_value;
            }
        }

        #[cfg(target_os = "linux")]
        {
            // Prefer Linux cpufreq if available: this is usually the most “Task Manager-like”
            // live frequency signal on bare-metal Linux.
            if let Some(mhz) = read_linux_cpufreq_mhz() {
                return Some(mhz);
            }
        }

        // Cross-platform fallback: average per-CPU sysinfo frequency.
        let freqs: Vec<u64> = self
            .sys
            .cpus()
            .iter()
            .map(|c| c.frequency())
            .filter(|f| *f > 0)
            .collect();

        if freqs.is_empty() {
            return None;
        }

        let sum: u64 = freqs.iter().sum();
        Some(sum / freqs.len() as u64)
    }

    #[cfg(target_os = "linux")]
    fn read_linux_cpufreq_mhz() -> Option<u64> {
        // Reads e.g. /sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq (kHz)
        // and averages across CPUs.
        let base = Path::new("/sys/devices/system/cpu");
        let mut values_khz: Vec<u64> = Vec::new();

        let entries = fs::read_dir(base).ok()?;
        for e in entries.flatten() {
            let name = e.file_name();
            let name = name.to_string_lossy();
            if !name.starts_with("cpu") {
                continue;
            }
            // cpu0, cpu1...
            if name[3..].chars().any(|c| !c.is_ascii_digit()) {
                continue;
            }

            let path = e.path().join("cpufreq").join("scaling_cur_freq");
            let Ok(s) = fs::read_to_string(&path) else {
                continue;
            };
            let Ok(khz) = s.trim().parse::<u64>() else {
                continue;
            };
            if khz > 0 {
                values_khz.push(khz);
            }
        }

        if values_khz.is_empty() {
            return None;
        }

        let sum: u64 = values_khz.iter().sum();
        let avg_khz = sum / values_khz.len() as u64;
        Some((avg_khz + 500) / 1000) // kHz -> MHz (rounded)
    }

    pub fn get_memory_stats(&self) -> (u64, u64) {
        (self.sys.used_memory(), self.sys.total_memory())
    }

    /// Best-effort RAM speed in MHz.
    ///
    /// - Windows: Uses `Win32_PhysicalMemory.Speed/ConfiguredClockSpeed` and returns the maximum
    ///   module speed.
    /// - Linux: Best-effort via `dmidecode` (DMI/SMBIOS). This often requires root privileges and
    ///   may be unavailable in some VMs.
    pub fn get_ram_speed_mhz(&mut self) -> Option<u64> {
        #[cfg(windows)]
        {
            #[allow(non_snake_case)]
            #[derive(Debug, Deserialize)]
            struct Win32PhysicalMemory {
                Speed: Option<u32>,
                ConfiguredClockSpeed: Option<u32>,
            }

            let wmi_con = self.ensure_wmi()?;
            let modules: Vec<Win32PhysicalMemory> = wmi_con
                .raw_query("SELECT Speed, ConfiguredClockSpeed FROM Win32_PhysicalMemory")
                .ok()?;

            let mut best: Option<u64> = None;
            for m in modules {
                let s = m
                    .ConfiguredClockSpeed
                    .or(m.Speed)
                    .map(|v| v as u64)
                    .filter(|v| *v > 0);
                if let Some(v) = s {
                    best = Some(best.map(|b| b.max(v)).unwrap_or(v));
                }
            }
            best
        }

        #[cfg(target_os = "linux")]
        {
            if self.linux_ram_speed_attempted {
                return self.cached_ram_speed_mhz;
            }

            let v = Self::read_linux_ram_speed_mhz_dmidecode();
            self.linux_ram_speed_attempted = true;
            self.cached_ram_speed_mhz = v;
            v
        }

        #[cfg(all(not(windows), not(target_os = "linux")))]
        {
            None
        }
    }

    #[cfg(target_os = "linux")]
    fn read_linux_ram_speed_mhz_dmidecode() -> Option<u64> {
        // dmidecode output examples (varies by platform/BIOS):
        //   "Speed: 3200 MT/s"
        //   "Configured Memory Speed: 2666 MT/s"
        // Some machines/VMs show "Unknown" or omit the field.
        let output = Command::new("dmidecode")
            .args(["--type", "memory"])
            .output()
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut best: Option<u64> = None;

        for line in stdout.lines().map(str::trim) {
            if !(line.starts_with("Speed:") || line.starts_with("Configured Memory Speed:")) {
                continue;
            }

            // Extract the first integer found on the line.
            let mut num: Option<u64> = None;
            let mut acc: u64 = 0;
            let mut in_digits = false;
            for ch in line.chars() {
                if ch.is_ascii_digit() {
                    in_digits = true;
                    acc = acc
                        .saturating_mul(10)
                        .saturating_add((ch as u8 - b'0') as u64);
                } else if in_digits {
                    num = Some(acc);
                    break;
                }
            }
            if num.is_none() && in_digits {
                num = Some(acc);
            }

            let Some(v) = num.filter(|v| *v > 0) else {
                continue;
            };

            best = Some(best.map(|b| b.max(v)).unwrap_or(v));
        }

        best
    }

    pub fn get_disk_space_summary(&self) -> String {
        // Short summary used in headers: show the busiest disk (highest used %) if available.
        let mut best: Option<(f64, String)> = None;
        for d in self.disks.list() {
            let total = d.total_space().max(1);
            let used = total.saturating_sub(d.available_space());
            let pct = (used as f64 / total as f64) * 100.0;
            let mount = d.mount_point().display().to_string();
            let used_gb = used as f64 / 1_000_000_000.0;
            let total_gb = total as f64 / 1_000_000_000.0;
            let text = format!("{}: {:.1}/{:.1} GB ({:.0}%)", mount, used_gb, total_gb, pct);
            match &best {
                Some((best_pct, _)) if *best_pct >= pct => {}
                _ => best = Some((pct, text)),
            }
        }

        best.map(|(_, t)| t).unwrap_or_else(|| "N/A".to_string())
    }

    pub fn get_all_disks_lines(&self) -> Vec<String> {
        let mut rows: Vec<(f64, String)> = self
            .disks
            .list()
            .iter()
            .map(|d| {
                let total = d.total_space().max(1);
                let used = total.saturating_sub(d.available_space());
                let pct = (used as f64 / total as f64) * 100.0;
                let mount = d.mount_point().display().to_string();
                let fs = d.file_system().to_string_lossy().to_string();
                let used_gb = used as f64 / 1_000_000_000.0;
                let total_gb = total as f64 / 1_000_000_000.0;
                (
                    pct,
                    format!(
                        "{:<8} {:>5.1}/{:<5.1} GB {:>3.0}%  {}",
                        mount, used_gb, total_gb, pct, fs
                    ),
                )
            })
            .collect();

        rows.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
        rows.into_iter().map(|(_, line)| line).collect()
    }

    pub fn get_system_uptime(&self) -> u64 {
        System::uptime()
    }

    /// True disk throughput via OS counters (Windows only).
    ///
    /// Returns a map from PhysicalDisk instance name (e.g. "_Total", "0 C:") to (read_mibs, write_mibs).
    pub fn get_physical_disk_throughput_mibs(
        &mut self,
    ) -> std::collections::HashMap<String, (f64, f64)> {
        #[cfg(windows)]
        {
            #[allow(non_snake_case)]
            #[derive(Debug, Deserialize)]
            struct Win32PhysicalDisk {
                Name: String,
                #[serde(alias = "DiskReadBytesPerSec")]
                #[serde(alias = "DiskReadBytesPersec")]
                DiskReadBytesPersec: Option<u64>,
                #[serde(alias = "DiskWriteBytesPerSec")]
                #[serde(alias = "DiskWriteBytesPersec")]
                DiskWriteBytesPersec: Option<u64>,
            }

            let mut out = std::collections::HashMap::new();
            let Some(wmi_con) = self.ensure_wmi() else {
                return out;
            };

            let rows: Vec<Win32PhysicalDisk> = wmi_con
                .raw_query(
                    "SELECT Name, DiskReadBytesPersec, DiskWriteBytesPersec FROM Win32_PerfFormattedData_PerfDisk_PhysicalDisk",
                )
                .unwrap_or_default();

            for r in rows {
                let read_bps = r.DiskReadBytesPersec.unwrap_or(0);
                let write_bps = r.DiskWriteBytesPersec.unwrap_or(0);
                out.insert(
                    r.Name,
                    (
                        read_bps as f64 / 1_048_576.0,
                        write_bps as f64 / 1_048_576.0,
                    ),
                );
            }

            out
        }

        #[cfg(not(windows))]
        {
            std::collections::HashMap::new()
        }
    }

    pub fn collect_processes(&self) -> Vec<(u32, ProcessMetadata, ProcessMetrics)> {
        let process_count = self.sys.processes().len();
        let mut collected = Vec::with_capacity(process_count);

        for (pid, process) in self.sys.processes() {
            let pid_u32 = pid.as_u32();

            let metadata = ProcessMetadata {
                pid: pid_u32,
                name: process.name().to_string(),
                parent_pid: process.parent().map(|p| p.as_u32()),
                command: process.cmd().to_vec(),
                start_time: process.start_time(),
                uid: process.user_id().map(|u| u.to_string()),
            };

            let metrics = ProcessMetrics {
                cpu_usage: process.cpu_usage(),
                memory_usage: process.memory(),
                virtual_memory: process.virtual_memory(),
                disk_read: process.disk_usage().read_bytes,
                disk_write: process.disk_usage().written_bytes,
                status: process.status().to_string(),
                thread_count: None,
            };

            collected.push((pid_u32, metadata, metrics));
        }

        collected
    }
}
