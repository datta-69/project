use crate::models::{ProcessMetadata, ProcessMetrics, ProcessRisk, RiskLevel};

// Risk calculation constants
const CPU_WEIGHT: f32 = 40.0;
const MEM_WEIGHT: f32 = 30.0;
const SUSPICIOUS_WEIGHT: f32 = 20.0;
const SHELL_SUSPICIOUS_WEIGHT: f32 = 8.0;
const CPU_HIGH_THRESHOLD: f32 = 80.0;
const CPU_MEDIUM_THRESHOLD: f32 = 20.0;
const MEM_HIGH_THRESHOLD_MIB: f32 = 1000.0;
const MEM_BASELINE_MIB: f32 = 1024.0; // 1 GiB
const SHELL_ACTIVITY_CPU_THRESHOLD: f32 = 20.0;
const SHELL_ACTIVITY_MEM_THRESHOLD_MIB: f32 = 200.0;

#[derive(Debug, Default)]
pub struct BehaviorAnalyzer {
    // History of metrics for anomaly detection could go here
}

impl BehaviorAnalyzer {
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn analyze_process(
        &self,
        metadata: &ProcessMetadata,
        metrics: &ProcessMetrics,
    ) -> ProcessRisk {
        let mut raw_score: f32 = 0.0;
        let mut factors = Vec::with_capacity(3);

        // 1. CPU Impact (Max 40 points)
        let cpu_factor = metrics.cpu_usage.min(100.0);
        let cpu_score = (cpu_factor / 100.0) * CPU_WEIGHT;
        raw_score += cpu_score;

        if metrics.cpu_usage > CPU_HIGH_THRESHOLD {
            factors.push(format!("Critical CPU: {:.1}%", metrics.cpu_usage));
        } else if metrics.cpu_usage > CPU_MEDIUM_THRESHOLD {
            factors.push(format!("High CPU: {:.1}%", metrics.cpu_usage));
        }

        // 2. Memory Impact (Max 30 points)
        let mem_usage_mib = metrics.memory_mib() as f32;
        let mem_score = (mem_usage_mib / MEM_BASELINE_MIB).min(1.0) * MEM_WEIGHT;
        raw_score += mem_score;

        if mem_usage_mib > MEM_HIGH_THRESHOLD_MIB {
            factors.push(format!("High Memory: {:.0} MiB", mem_usage_mib));
        }

        // 3. Suspicious Qualities (Max 20 points)
        static SUSPICIOUS_NAMES: &[&str] = &[
            "nc",
            "netcat",
            "nmap",
            "wireshark",
            "keylogger",
            "powershell.exe",
            "cmd.exe",
            "mimikatz",
        ];

        static SHELL_NAMES: &[&str] = &["powershell.exe", "cmd.exe", "pwsh", "bash", "zsh"];

        let shell_encoded_flags = ["-enc", "-encodedcommand", "-nop", "-w hidden", "--command"];

        let name_lower = metadata.name.to_lowercase();
        let command_line = metadata.command.join(" ").to_lowercase();
        let shells_enabled = std::env::var("PM_ENABLE_SHELL_RISK")
            .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
            .unwrap_or(false);

        let is_shell = SHELL_NAMES.iter().any(|&name| name_lower.contains(name));
        let shell_activity = metrics.cpu_usage >= SHELL_ACTIVITY_CPU_THRESHOLD
            || mem_usage_mib >= SHELL_ACTIVITY_MEM_THRESHOLD_MIB
            || shell_encoded_flags
                .iter()
                .any(|flag| command_line.contains(flag));

        let is_suspicious_name = SUSPICIOUS_NAMES
            .iter()
            .any(|&suspicious| name_lower.contains(suspicious));

        if is_suspicious_name {
            if is_shell {
                if shells_enabled && shell_activity {
                    raw_score += SHELL_SUSPICIOUS_WEIGHT;
                    factors.push(format!("Shell Activity: {}", metadata.name));
                }
            } else {
                raw_score += SUSPICIOUS_WEIGHT;
                factors.push(format!("Suspicious Name: {}", metadata.name));
            }
        }

        // 4. Normalize score
        let final_score = raw_score.min(100.0) as u8;

        let level = match final_score {
            0..=19 => RiskLevel::Low,
            20..=59 => RiskLevel::Medium,
            60..=89 => RiskLevel::High,
            _ => RiskLevel::Critical,
        };

        ProcessRisk {
            score: final_score,
            level,
            factors,
        }
    }
}
