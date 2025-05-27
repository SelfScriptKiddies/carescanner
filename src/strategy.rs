// Strategy is a method of scanning - host-first, random port order host-first, round-robin, etc.
pub mod round_robin;
pub mod host_first;

use crate::modes::Target;
use crate::configuration::TargetList;
use crate::configuration::{self, PortList};
use enum_dispatch::enum_dispatch;

#[enum_dispatch] 
pub trait ScanStrategyTrait {
    fn create_targets<'a>(
        &'a self,
        hosts:  &'a TargetList,
        ports:  &'a PortList,
    ) -> Box<dyn Iterator<Item = Target> + 'a>;
}

impl ScanStrategyTrait for configuration::ScanStrategy {
    fn create_targets<'a>(
        &'a self,
        hosts: &'a TargetList,
        ports: &'a PortList,
    ) -> Box<dyn Iterator<Item = Target> + 'a> {
        match self {
            configuration::ScanStrategy::HostFirst => host_first::HostFirstStrategy.create_targets(hosts, ports),
            configuration::ScanStrategy::RoundRobin => round_robin::RoundRobinStrategy.create_targets(hosts, ports)
        }
    }
}
