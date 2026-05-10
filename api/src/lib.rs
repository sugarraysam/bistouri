pub mod config;

#[cfg(feature = "kube")]
pub mod cr;

pub mod v1 {
    tonic::include_proto!("bistouri.v1");
}
