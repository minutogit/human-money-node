//! # Spec 17: Topology Telemetry & Social Defense Layer
//!
//! Zero-I/O, deterministic in-memory telemetry for humoco-node.

pub const WARN_GATEWAY_CONCENTRATION: &str = "WARN_GATEWAY_CONCENTRATION";
pub const INFO_SHARD_OPERATOR_DOMINANCE: &str = "INFO_SHARD_OPERATOR_DOMINANCE";

/// Diagnostic level for dashboard warnings.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum WarningLevel {
    /// High percentage of locks originate from <= 2 ingress sources.
    WarnGatewayConcentration,
    /// Many shard nodes reside in the same IP subnet.
    InfoShardOperatorDominance,
}

impl WarningLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::WarnGatewayConcentration => WARN_GATEWAY_CONCENTRATION,
            Self::InfoShardOperatorDominance => INFO_SHARD_OPERATOR_DOMINANCE,
        }
    }

    pub fn triggers_auto_ban(&self) -> bool {
        false
    }

    pub fn is_warn(&self) -> bool {
        matches!(self, Self::WarnGatewayConcentration)
    }

    pub fn is_info(&self) -> bool {
        matches!(self, Self::InfoShardOperatorDominance)
    }
}

impl std::fmt::Display for WarningLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A non-authoritative warning emitted for the operator dashboard.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiagnosticWarning {
    pub level: WarningLevel,
    pub message: String,
    pub details: Option<String>,
}

impl DiagnosticWarning {
    pub fn local(level: WarningLevel, message: impl Into<String>) -> Self {
        Self {
            level,
            message: message.into(),
            details: None,
        }
    }
}

/// Evaluates gateway concentration ratio: the fraction of locks/traffic originating
/// from the top <= 2 ingress sources (0.0 to 1.0).
pub fn evaluate_gateway_concentration_ratio(source_counts: &[usize]) -> f64 {
    let total: usize = source_counts.iter().sum();
    if total == 0 {
        return 0.0;
    }
    let mut sorted = source_counts.to_vec();
    sorted.sort_unstable_by(|a, b| b.cmp(a));
    let top_2_sum: usize = sorted.iter().take(2).sum();
    top_2_sum as f64 / total as f64
}

/// Detects gateway concentration: if >= 20 total locks and >= 80% originate from <= 2 ingress sources.
/// INV-1701: non-authoritative warning only.
pub fn detect_gateway_concentration(source_counts: &[usize]) -> Option<DiagnosticWarning> {
    let total: usize = source_counts.iter().sum();
    if total >= 20 {
        let ratio = evaluate_gateway_concentration_ratio(source_counts);
        if ratio >= 0.8 {
            return Some(DiagnosticWarning::local(
                WarningLevel::WarnGatewayConcentration,
                format!(
                    "High gateway concentration: top ingress sources provide {:.1}% of {} total locks (>= 80% threshold). Consider diversifying ingress endpoints.",
                    ratio * 100.0,
                    total
                ),
            ));
        }
    }
    None
}

/// Evaluates maximum shard subnet dominance ratio (0.0 to 1.0).
pub fn evaluate_subnet_dominance_max(subnet_node_counts: &[usize]) -> f64 {
    let total: usize = subnet_node_counts.iter().sum();
    if total == 0 {
        return 0.0;
    }
    let max_in_subnet = subnet_node_counts.iter().copied().max().unwrap_or(0);
    max_in_subnet as f64 / total as f64
}

/// Detects shard operator dominance: when a single subnet hosts > 50% of nodes in a shard (N >= 3).
/// INV-1701: non-authoritative informational notice only.
pub fn detect_shard_operator_dominance(
    shard_id: u16,
    subnet_node_counts: &[usize],
) -> Option<DiagnosticWarning> {
    let total: usize = subnet_node_counts.iter().sum();
    if total >= 3 {
        let max_ratio = evaluate_subnet_dominance_max(subnet_node_counts);
        if max_ratio > 0.5 {
            return Some(DiagnosticWarning::local(
                WarningLevel::InfoShardOperatorDominance,
                format!(
                    "Shard {} operator dominance: single subnet contains {:.1}% of shard nodes ({} of {}).",
                    shard_id,
                    max_ratio * 100.0,
                    subnet_node_counts.iter().copied().max().unwrap_or(0),
                    total
                ),
            ));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gateway_concentration() {
        assert_eq!(evaluate_gateway_concentration_ratio(&[]), 0.0);
        let balanced = [10, 10, 10, 10];
        assert_eq!(evaluate_gateway_concentration_ratio(&balanced), 0.5);
        assert!(detect_gateway_concentration(&balanced).is_none());

        let concentrated = [85, 5, 5, 5];
        assert!(evaluate_gateway_concentration_ratio(&concentrated) > 0.8);
        let warn = detect_gateway_concentration(&concentrated).expect("warning expected");
        assert_eq!(warn.level, WarningLevel::WarnGatewayConcentration);
        assert!(!warn.level.triggers_auto_ban());
    }

    #[test]
    fn test_subnet_dominance() {
        assert_eq!(evaluate_subnet_dominance_max(&[]), 0.0);
        let subnets = [1, 1, 1];
        assert!(detect_shard_operator_dominance(1, &subnets).is_none());

        let dominant = [3, 1];
        let warn = detect_shard_operator_dominance(1, &dominant).expect("warning expected");
        assert_eq!(warn.level, WarningLevel::InfoShardOperatorDominance);
        assert!(!warn.level.triggers_auto_ban());
    }
}
