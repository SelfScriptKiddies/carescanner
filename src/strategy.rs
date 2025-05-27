// Strategy is a method of scanning - host-first, random port order host-first, round-robin, etc.
pub mod round_robin;
pub mod host_first;

use crate::modes::Target;
use crate::configuration::TargetList;
use crate::configuration::PortList;

pub trait ScanStrategy {
    fn create_targets(targets: &TargetList, ports: &PortList) -> impl Iterator<Item = Target>;
}