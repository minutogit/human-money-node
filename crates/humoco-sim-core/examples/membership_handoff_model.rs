#![forbid(unsafe_code)]
//! Experimental executable model, not the production protocol or a general proof.
//! Initial configuration recognition and authentication are explicit assumptions.
#[path = "membership_handoff/bootstrap.rs"]
mod bootstrap;
#[path = "membership_handoff/capacity.rs"]
mod capacity;
#[path = "membership_handoff/lifecycle.rs"]
mod lifecycle;
#[path = "membership_handoff/model.rs"]
mod model;

fn main() {
    if let Err(error) = model::run_cli() {
        eprintln!("FAIL: {error}");
        std::process::exit(1);
    }
}
