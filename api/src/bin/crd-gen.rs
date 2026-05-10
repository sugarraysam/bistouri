//! CRD generator for Bistouri.
//!
//! Generates the `BistouriConfig` CustomResourceDefinition YAML.
//! The schema, CEL rules, and CR type all live in `bistouri_api::cr`.
//!
//! Usage:
//!   cargo run -q -p bistouri-api --bin crd-gen > deployment/crd/bistouriconfig.yaml
//!   # or via make:
//!   make generate-crd

use bistouri_api::cr::BistouriConfig;
use kube::core::CustomResourceExt;

fn main() {
    let crd = BistouriConfig::crd();
    println!(
        "{}",
        serde_json::to_string_pretty(&crd).expect("CRD serialization failed")
    );
}
