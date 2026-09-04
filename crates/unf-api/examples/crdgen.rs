use kube::CustomResourceExt;
use unf_api::{
    EgressInternetClassification, EgressPolicy, EgressPool, EgressReachabilityObservation,
    EgressReachabilityPlan, SecurityPolicy,
};

fn main() {
    let kind = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!(
            "usage: crdgen <security-policy|egress-pool|egress-policy|egress-internet-classification|egress-reachability-plan|egress-reachability-observation>"
        );
        std::process::exit(2);
    });
    let crd = match kind.as_str() {
        "security-policy" => SecurityPolicy::crd(),
        "egress-pool" => EgressPool::crd(),
        "egress-policy" => EgressPolicy::crd(),
        "egress-internet-classification" => EgressInternetClassification::crd(),
        "egress-reachability-plan" => EgressReachabilityPlan::crd(),
        "egress-reachability-observation" => EgressReachabilityObservation::crd(),
        _ => {
            eprintln!("unknown CRD kind {kind:?}");
            std::process::exit(2);
        }
    };
    print!(
        "{}",
        serde_yaml::to_string(&crd).expect("CRD must serialize")
    );
}
