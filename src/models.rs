use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessMetadata {
    pub pid: u32,
    pub name: String,
    pub parent_pid: Option<u32>,
    pub command: Vec<String>,
    pub start_time: u64,
    pub uid: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessMetrics {
    pub cpu_usage: f32,
    pub memory_usage: u64,   // In KiB (as reported by sysinfo)
    pub virtual_memory: u64, // In KiB
    pub disk_read: u64,      // In bytes
    pub disk_write: u64,     // In bytes
    pub status: String,
    pub thread_count: Option<u32>,
}

#[allow(dead_code)]
impl ProcessMetrics {
    /// Get memory usage in MiB
    #[inline]
    pub fn memory_mib(&self) -> f64 {
        self.memory_usage as f64 / 1024.0
    }

    /// Get memory usage in GiB
    #[inline]
    pub fn memory_gib(&self) -> f64 {
        self.memory_usage as f64 / 1_048_576.0
    }

    /// Get disk read in KiB
    #[inline]
    pub fn disk_read_kib(&self) -> u64 {
        self.disk_read / 1024
    }

    /// Get disk write in KiB
    #[inline]
    pub fn disk_write_kib(&self) -> u64 {
        self.disk_write / 1024
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessRisk {
    pub score: u8, // 0-100
    pub level: RiskLevel,
    pub factors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoredProcess {
    pub metadata: ProcessMetadata,
    pub metrics_history: VecDeque<(DateTime<Utc>, ProcessMetrics)>,
    pub current_risk: ProcessRisk,
    pub lineage_path: Vec<u32>, // Path from root to this process
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventType {
    ProcessCreated,
    ProcessStarted, // Added this since app.rs uses it
    ProcessTerminated,
    HighResourceUsage,
    PrivilegeEscalation,
    AnomalyDetected,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemEvent {
    pub timestamp: DateTime<Utc>,
    pub event_type: EventType,
    pub pid: u32,
    pub description: String,
    pub severity: RiskLevel,
}
