//! Read-only native layout discovery. No BPF load, TC attachment or admission.
use unf_link::kernel_layout::KernelDeviceLayout;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args_os().len() != 1 {
        return Err("no arguments: reads only the current kernel BTF".into());
    }
    let layout = KernelDeviceLayout::discover()?;
    let offsets = layout.offsets();
    println!(
        "{}",
        serde_json::json!({
            "schemaVersion": 1, "scope": "kernel-device-layout-metadata", "wordBytes": 8,
            "skbDevice": offsets.skb_device, "deviceIndex": offsets.device_index,
            "deviceNet": offsets.device_net, "netCookie": offsets.net_cookie,
            "devicePeer": offsets.device_peer, "deviceFlags": offsets.device_flags,
            "deviceAlias": offsets.device_alias, "aliasData": offsets.alias_data,
            "btfDigest": layout.btf_digest(), "kernelAdmitted": false,
        })
    );
    Ok(())
}
