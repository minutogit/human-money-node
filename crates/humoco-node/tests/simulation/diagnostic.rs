//! DiagnosticReporter – soft assertions without panics.
//!
//! Collects failures and reports them at the end of a simulation phase
//! instead of aborting immediately. Mirrors `INV-1701` non-authoritative
//! telemetry philosophy.

use std::fmt::Debug;

/// Severity of a diagnostic event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagnosticLevel {
    Info,
    Warn,
    Error,
}

/// Single diagnostic entry.
#[derive(Debug, Clone)]
pub struct DiagnosticEntry {
    pub level: DiagnosticLevel,
    pub message: String,
    pub phase: String,
}

/// Collector for soft assertions.
#[derive(Debug, Clone)]
pub struct DiagnosticReporter {
    entries: Vec<DiagnosticEntry>,
    checks_total: usize,
    checks_passed: usize,
    current_phase: String,
}

impl DiagnosticReporter {
    /// Creates a new reporter with empty state.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            checks_total: 0,
            checks_passed: 0,
            current_phase: "init".to_string(),
        }
    }

    /// Sets the current phase label for subsequent diagnostics.
    pub fn set_phase(&mut self, phase: impl Into<String>) {
        self.current_phase = phase.into();
    }

    /// Returns the current phase.
    pub fn phase(&self) -> &str {
        &self.current_phase
    }

    /// Soft assertion: records success/failure without panicking.
    /// Returns true if condition holds.
    pub fn check(&mut self, condition: bool, msg: impl Into<String>) -> bool {
        self.checks_total += 1;
        if condition {
            self.checks_passed += 1;
            true
        } else {
            let m = msg.into();
            self.entries.push(DiagnosticEntry {
                level: DiagnosticLevel::Error,
                message: m.clone(),
                phase: self.current_phase.clone(),
            });
            eprintln!("[DIAG][{}][FAIL] {}", self.current_phase, m);
            false
        }
    }

    /// Soft equality check.
    pub fn check_eq<T: PartialEq + Debug>(
        &mut self,
        left: &T,
        right: &T,
        context: impl Into<String>,
    ) -> bool {
        let ok = left == right;
        if ok {
            self.checks_total += 1;
            self.checks_passed += 1;
            true
        } else {
            let msg = format!(
                "{}: left = {:?}, right = {:?}",
                context.into(),
                left,
                right
            );
            self.check(false, msg)
        }
    }

    /// Logs an informational message (does not count as check).
    pub fn info(&mut self, msg: impl Into<String>) {
        let m = msg.into();
        self.entries.push(DiagnosticEntry {
            level: DiagnosticLevel::Info,
            message: m.clone(),
            phase: self.current_phase.clone(),
        });
        println!("[DIAG][{}][INFO] {}", self.current_phase, m);
    }

    /// Logs a warning (does not fail the test).
    pub fn warn(&mut self, msg: impl Into<String>) {
        let m = msg.into();
        self.entries.push(DiagnosticEntry {
            level: DiagnosticLevel::Warn,
            message: m.clone(),
            phase: self.current_phase.clone(),
        });
        eprintln!("[DIAG][{}][WARN] {}", self.current_phase, m);
    }

    /// Returns true if any error-level diagnostic was recorded.
    pub fn has_failures(&self) -> bool {
        self.entries
            .iter()
            .any(|e| e.level == DiagnosticLevel::Error)
    }

    /// Returns total number of checks.
    pub fn total_checks(&self) -> usize {
        self.checks_total
    }

    /// Returns number of passed checks.
    pub fn passed_checks(&self) -> usize {
        self.checks_passed
    }

    /// Returns failure count.
    pub fn failure_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| e.level == DiagnosticLevel::Error)
            .count()
    }

    /// Prints a summary and panics if there were failures.
    /// Use at the end of a test to enforce soft assertions.
    pub fn assert_no_failures(&self) {
        if self.has_failures() {
            eprintln!("=== Diagnostic Summary ===");
            eprintln!(
                "Phase: {} | Checks: {}/{} passed | Failures: {}",
                self.current_phase,
                self.checks_passed,
                self.checks_total,
                self.failure_count()
            );
            for e in self
                .entries
                .iter()
                .filter(|e| e.level == DiagnosticLevel::Error)
            {
                eprintln!("  [{}] {}", e.phase, e.message);
            }
            panic!(
                "DiagnosticReporter: {} soft assertion(s) failed (see above)",
                self.failure_count()
            );
        } else {
            println!(
                "[DIAG][{}] All {} checks passed",
                self.current_phase, self.checks_total
            );
        }
    }

    /// Returns a snapshot of all entries.
    pub fn entries(&self) -> &[DiagnosticEntry] {
        &self.entries
    }

    /// Clears recorded entries but keeps counters.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Prints a human-readable report without panicking.
    pub fn report(&self) {
        println!("--- Diagnostic Report [{}] ---", self.current_phase);
        println!(
            "Checks: {}/{} passed, {} warnings, {} errors",
            self.checks_passed,
            self.checks_total,
            self.entries
                .iter()
                .filter(|e| e.level == DiagnosticLevel::Warn)
                .count(),
            self.failure_count()
        );
        for e in &self.entries {
            let lvl = match e.level {
                DiagnosticLevel::Info => "INFO",
                DiagnosticLevel::Warn => "WARN",
                DiagnosticLevel::Error => "FAIL",
            };
            println!("  [{lvl}][{}] {}", e.phase, e.message);
        }
        println!("--- End Report ---");
    }
}

impl Default for DiagnosticReporter {
    fn default() -> Self {
        Self::new()
    }
}
