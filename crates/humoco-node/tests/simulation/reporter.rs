//! Reporter – structured phase reporting for the mesh simulator.
//!
//! Complements `DiagnosticReporter` with phase lifecycle logging
//! and a final simulation summary.

use std::time::Instant;

use crate::simulation::diagnostic::DiagnosticReporter;

/// Reporter that tracks phase transitions and timings.
#[derive(Debug)]
pub struct Reporter {
    sim_start: Instant,
    phase_start: Option<Instant>,
    current_phase: String,
    pub diagnostic: DiagnosticReporter,
}

impl Reporter {
    /// Creates a new reporter with current time as simulation start.
    pub fn new() -> Self {
        Self {
            sim_start: Instant::now(),
            phase_start: None,
            current_phase: "init".to_string(),
            diagnostic: DiagnosticReporter::new(),
        }
    }

    /// Begins a new phase. Logs start time and sets diagnostic phase.
    pub fn begin_phase(&mut self, name: impl Into<String>) {
        let name = name.into();
        self.current_phase = name.clone();
        self.phase_start = Some(Instant::now());
        self.diagnostic.set_phase(name.clone());
        println!("\n╔═══════════════════════════════════════════════════╗");
        println!("║  Phase: {:<41} ║", name);
        println!("╚═══════════════════════════════════════════════════╝");
    }

    /// Ends the current phase successfully.
    pub fn end_phase_ok(&mut self) {
        if let Some(start) = self.phase_start.take() {
            let elapsed = start.elapsed();
            println!(
                "✓ Phase '{}' completed in {:.2?} (total sim: {:.2?})",
                self.current_phase,
                elapsed,
                self.sim_start.elapsed()
            );
        } else {
            println!("✓ Phase '{}' completed", self.current_phase);
        }
    }

    /// Ends the current phase with a diagnostic failure note (does not panic).
    pub fn end_phase_with_warnings(&mut self) {
        let failures = self.diagnostic.failure_count();
        if failures > 0 {
            eprintln!(
                "⚠ Phase '{}' finished with {} soft failure(s)",
                self.current_phase, failures
            );
        }
        self.end_phase_ok();
    }

    /// Logs a step within the current phase.
    pub fn step(&mut self, msg: impl Into<String>) {
        let m = msg.into();
        println!("[{}] {}", self.current_phase, m);
        self.diagnostic.info(m);
    }

    /// Proxy to diagnostic `check`.
    pub fn check(&mut self, condition: bool, msg: impl Into<String>) -> bool {
        self.diagnostic.check(condition, msg)
    }

    /// Proxy to diagnostic `check_eq`.
    pub fn check_eq<T: std::fmt::Debug + PartialEq>(
        &mut self,
        left: &T,
        right: &T,
        context: impl Into<String>,
    ) -> bool {
        self.diagnostic.check_eq(left, right, context)
    }

    /// Proxy to diagnostic `warn`.
    pub fn warn(&mut self, msg: impl Into<String>) {
        self.diagnostic.warn(msg);
    }

    /// Proxy to diagnostic `info`.
    pub fn info(&mut self, msg: impl Into<String>) {
        self.diagnostic.info(msg);
    }

    /// Prints the final simulation summary.
    pub fn final_report(&self) {
        println!("\n═══════════════════════════════════════════════════════");
        println!("  Mesh Simulation Summary");
        println!("═══════════════════════════════════════════════════════");
        println!("Total wall time: {:.2?}", self.sim_start.elapsed());
        self.diagnostic.report();
        println!("═══════════════════════════════════════════════════════\n");
    }

    /// Asserts that no soft failures were recorded; panics with diagnostic dump otherwise.
    pub fn assert_clean(&self) {
        self.diagnostic.assert_no_failures();
    }

    /// Returns the underlying diagnostic reporter mutably.
    pub fn diagnostic_mut(&mut self) -> &mut DiagnosticReporter {
        &mut self.diagnostic
    }
}

impl Default for Reporter {
    fn default() -> Self {
        Self::new()
    }
}
