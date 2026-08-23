use kube::CustomResourceExt;
use unf_api::SecurityPolicy;

fn main() {
    print!(
        "{}",
        serde_yaml::to_string(&SecurityPolicy::crd()).expect("SecurityPolicy CRD must serialize")
    );
}
