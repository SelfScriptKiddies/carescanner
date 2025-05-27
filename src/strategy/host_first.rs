use super::*;
use crate::modes::Target;

pub struct HostFirstStrategy;

impl ScanStrategyTrait for HostFirstStrategy {
    fn create_targets<'a>(
        &'a self,
        hosts: &'a TargetList,
        ports: &'a PortList,
    ) -> Box<dyn Iterator<Item = Target> + 'a> {
        Box::new(
            hosts.targets.iter().flat_map(move |ip| {
                ports.ports.iter().map(move |port| Target { ip: ip.clone(), port: *port })
            }),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_first_order() {
        let targets = TargetList { targets: vec!["192.168.1.1".to_string(), "192.168.1.2".to_string()] };
        let ports = PortList { ports: vec![80, 443] };

        let targets_iter = HostFirstStrategy.create_targets(&targets, &ports);
        let targets_vec = targets_iter.collect::<Vec<Target>>();
                
        assert_eq!(targets_vec.len(), 4);
        assert_eq!(targets_vec[0].ip, "192.168.1.1");
        assert_eq!(targets_vec[0].port, 80);
        assert_eq!(targets_vec[1].ip, "192.168.1.1");
        assert_eq!(targets_vec[1].port, 443);
        assert_eq!(targets_vec[2].ip, "192.168.1.2");
        assert_eq!(targets_vec[2].port, 80);
        assert_eq!(targets_vec[3].ip, "192.168.1.2");
        assert_eq!(targets_vec[3].port, 443);
    }
}