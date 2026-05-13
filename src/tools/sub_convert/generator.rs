use super::gen_clash;
use super::gen_singbox;
use super::gen_subscription;
use super::types::{ProxyNode, ProxyProtocol};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetFormat {
    Subscription,
    V2ray,
    Singbox,
    HiddifySafe,
    Clash,
}

impl Default for TargetFormat {
    fn default() -> Self {
        Self::Subscription
    }
}

impl TargetFormat {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Subscription => "subscription",
            Self::V2ray => "v2ray",
            Self::Singbox => "singbox",
            Self::HiddifySafe => "hiddify_safe",
            Self::Clash => "clash",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ProxyInfo {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub protocol: String,
}

#[derive(Debug, Clone)]
pub struct GenerateResult {
    pub content: String,
    pub proxy_info: Vec<ProxyInfo>,
    pub outbounds_count: usize,
}

fn node_to_proxy_info(node: &ProxyNode) -> ProxyInfo {
    ProxyInfo {
        name: node.name.clone(),
        server: node.server.clone(),
        port: node.port,
        protocol: node.protocol.protocol_str().to_string(),
    }
}

fn filter_hiddify_safe_nodes(nodes: &[ProxyNode]) -> Vec<ProxyNode> {
    nodes
        .iter()
        .filter(|node| {
            matches!(
                node.protocol,
                ProxyProtocol::Vmess | ProxyProtocol::Vless | ProxyProtocol::Trojan
            ) && node.tls_enabled
                && !node.reality_enabled
        })
        .cloned()
        .collect()
}

pub fn generate_output(
    nodes: &[ProxyNode],
    format: &TargetFormat,
    include_direct: bool,
    include_dns: bool,
) -> Result<GenerateResult, String> {
    let selected_nodes;
    let nodes = match format {
        TargetFormat::HiddifySafe => {
            selected_nodes = filter_hiddify_safe_nodes(nodes);
            if selected_nodes.is_empty() {
                return Err(
                    "No Hiddify-safe nodes found; only TLS-enabled non-Reality vmess, vless, and trojan are supported"
                        .to_string(),
                );
            }
            selected_nodes.as_slice()
        }
        _ => nodes,
    };

    let proxy_info = nodes.iter().map(node_to_proxy_info).collect::<Vec<_>>();

    match format {
        TargetFormat::Subscription => Ok(GenerateResult {
            content: gen_subscription::generate_subscription_content(nodes),
            outbounds_count: proxy_info.len(),
            proxy_info,
        }),
        TargetFormat::V2ray => Ok(GenerateResult {
            content: gen_subscription::generate_v2ray_content(nodes),
            outbounds_count: proxy_info.len(),
            proxy_info,
        }),
        TargetFormat::Singbox | TargetFormat::HiddifySafe => {
            let config = gen_singbox::generate_singbox_config(
                nodes,
                include_direct,
                include_dns,
                matches!(format, TargetFormat::HiddifySafe),
            )?;
            let outbounds_count = config["outbounds"]
                .as_array()
                .map(|items| items.len())
                .unwrap_or(0);
            let content = serde_json::to_string_pretty(&config)
                .map_err(|e| format!("Failed to serialize sing-box config: {e}"))?;
            Ok(GenerateResult {
                content,
                proxy_info,
                outbounds_count,
            })
        }
        TargetFormat::Clash => Ok(GenerateResult {
            content: gen_clash::generate_clash_yaml(nodes, include_direct, include_dns)?,
            outbounds_count: proxy_info.len(),
            proxy_info,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::sub_convert::types::{ProxyNode, ProxyProtocol};

    #[test]
    fn test_generate_subscription_format() {
        let node = ProxyNode {
            method: "aes-128-gcm".to_string(),
            password: "pass".to_string(),
            ..ProxyNode::default_with(ProxyProtocol::Shadowsocks, "TestSS", "1.2.3.4", 443)
        };

        let result = generate_output(&[node], &TargetFormat::Subscription, false, false).unwrap();

        assert!(!result.content.is_empty());
        assert_eq!(result.proxy_info.len(), 1);
        assert_eq!(result.proxy_info[0].protocol, "shadowsocks");
        assert_eq!(result.outbounds_count, 1);
    }

    #[test]
    fn test_generate_v2ray_format_returns_plain_lines() {
        let node = ProxyNode {
            method: "aes-128-gcm".to_string(),
            password: "pass".to_string(),
            ..ProxyNode::default_with(ProxyProtocol::Shadowsocks, "TestSS", "1.2.3.4", 443)
        };

        let result = generate_output(&[node], &TargetFormat::V2ray, false, false).unwrap();

        assert!(result.content.starts_with("ss://"));
        assert!(!result.content.contains('\n'));
        assert_eq!(result.outbounds_count, 1);
    }

    #[test]
    fn test_generate_singbox_format() {
        let node = ProxyNode {
            password: "pass".to_string(),
            tls_enabled: true,
            tls_sni: "sni.com".to_string(),
            ..ProxyNode::default_with(ProxyProtocol::Trojan, "TestTrojan", "server.com", 443)
        };

        let result = generate_output(&[node], &TargetFormat::Singbox, false, false).unwrap();
        let config: serde_json::Value = serde_json::from_str(&result.content).unwrap();

        assert!(config["outbounds"].is_array());
        assert!(config["inbounds"].is_array());
        assert_eq!(result.proxy_info.len(), 1);
        assert_eq!(
            result.outbounds_count,
            config["outbounds"].as_array().unwrap().len()
        );
    }

    #[test]
    fn test_generate_hiddify_safe_filters_to_tls_enabled_non_reality_vmess_vless_and_trojan() {
        let tls_vmess = ProxyNode {
            uuid: "11111111-1111-1111-1111-111111111111".to_string(),
            tls_enabled: true,
            tls_sni: "vmess.example.com".to_string(),
            ..ProxyNode::default_with(ProxyProtocol::Vmess, "TLS VMess", "vmess.example.com", 443)
        };
        let tls_vless = ProxyNode {
            uuid: "22222222-2222-2222-2222-222222222222".to_string(),
            tls_enabled: true,
            tls_sni: "vless.example.com".to_string(),
            ..ProxyNode::default_with(ProxyProtocol::Vless, "TLS VLESS", "vless.example.com", 443)
        };
        let reality_vless = ProxyNode {
            uuid: "33333333-3333-3333-3333-333333333333".to_string(),
            tls_enabled: true,
            reality_enabled: true,
            tls_sni: "reality-vless.example.com".to_string(),
            ..ProxyNode::default_with(
                ProxyProtocol::Vless,
                "Reality VLESS",
                "reality-vless.example.com",
                443,
            )
        };
        let trojan = ProxyNode {
            password: "pass".to_string(),
            tls_enabled: true,
            tls_sni: "trojan.example.com".to_string(),
            ..ProxyNode::default_with(ProxyProtocol::Trojan, "Trojan", "trojan.example.com", 443)
        };
        let reality_trojan = ProxyNode {
            password: "pass".to_string(),
            tls_enabled: true,
            reality_enabled: true,
            tls_sni: "reality-trojan.example.com".to_string(),
            ..ProxyNode::default_with(
                ProxyProtocol::Trojan,
                "Reality Trojan",
                "reality-trojan.example.com",
                443,
            )
        };
        let plain_vmess = ProxyNode {
            uuid: "44444444-4444-4444-4444-444444444444".to_string(),
            tls_enabled: false,
            ..ProxyNode::default_with(ProxyProtocol::Vmess, "Plain VMess", "plain.example.com", 80)
        };
        let hy2 = ProxyNode {
            password: "pass".to_string(),
            tls_enabled: true,
            tls_sni: "hy2.example.com".to_string(),
            ..ProxyNode::default_with(ProxyProtocol::Hysteria2, "HY2", "hy2.example.com", 1443)
        };

        let result = generate_output(
            &[
                tls_vmess,
                tls_vless,
                reality_vless,
                trojan,
                reality_trojan,
                plain_vmess,
                hy2,
            ],
            &TargetFormat::HiddifySafe,
            false,
            false,
        )
        .unwrap();
        let config: serde_json::Value = serde_json::from_str(&result.content).unwrap();
        let outbounds = config["outbounds"].as_array().unwrap();

        assert_eq!(result.proxy_info.len(), 3);
        assert!(
            result
                .proxy_info
                .iter()
                .any(|proxy| proxy.protocol == "vmess" && proxy.name == "TLS VMess")
        );
        assert!(
            result
                .proxy_info
                .iter()
                .any(|proxy| proxy.protocol == "vless" && proxy.name == "TLS VLESS")
        );
        assert!(
            result
                .proxy_info
                .iter()
                .any(|proxy| proxy.protocol == "trojan" && proxy.name == "Trojan")
        );
        assert!(
            result
                .proxy_info
                .iter()
                .all(|proxy| proxy.name != "Reality VLESS" && proxy.name != "Reality Trojan")
        );
        assert!(
            result
                .proxy_info
                .iter()
                .all(|proxy| proxy.name != "Plain VMess")
        );
        assert!(outbounds.iter().any(|outbound| outbound["type"] == "vmess"));
        assert!(outbounds.iter().any(|outbound| outbound["type"] == "vless"));
        assert!(
            outbounds
                .iter()
                .any(|outbound| outbound["type"] == "trojan")
        );
        assert!(
            outbounds
                .iter()
                .all(|outbound| outbound["type"] != "hysteria2")
        );
    }

    #[test]
    fn test_generate_hiddify_safe_uses_dns_local_for_hostname_outbounds() {
        let tls_vmess = ProxyNode {
            uuid: "11111111-1111-1111-1111-111111111111".to_string(),
            tls_enabled: true,
            tls_sni: "vmess.example.com".to_string(),
            ..ProxyNode::default_with(ProxyProtocol::Vmess, "TLS VMess", "vmess.example.com", 443)
        };
        let tls_vless = ProxyNode {
            uuid: "22222222-2222-2222-2222-222222222222".to_string(),
            tls_enabled: true,
            tls_sni: "vless.example.com".to_string(),
            ..ProxyNode::default_with(ProxyProtocol::Vless, "TLS VLESS", "vless.example.com", 443)
        };
        let trojan = ProxyNode {
            password: "pass".to_string(),
            tls_enabled: true,
            tls_sni: "trojan.example.com".to_string(),
            ..ProxyNode::default_with(ProxyProtocol::Trojan, "Trojan", "trojan.example.com", 443)
        };

        let result = generate_output(
            &[tls_vmess, tls_vless, trojan],
            &TargetFormat::HiddifySafe,
            false,
            true,
        )
        .unwrap();
        let config: serde_json::Value = serde_json::from_str(&result.content).unwrap();
        let outbounds = config["outbounds"].as_array().unwrap();

        for outbound in outbounds
            .iter()
            .filter(|outbound| outbound["tag"] != "proxy")
        {
            assert_eq!(outbound["domain_resolver"], "dns-local");
        }
    }

    #[test]
    fn test_generate_hiddify_safe_skips_dns_local_for_ip_literal_outbounds() {
        let tls_vmess = ProxyNode {
            uuid: "55555555-5555-5555-5555-555555555555".to_string(),
            tls_enabled: true,
            tls_sni: "ip.example.com".to_string(),
            ..ProxyNode::default_with(ProxyProtocol::Vmess, "IP VMess", "1.2.3.4", 443)
        };
        let trojan = ProxyNode {
            password: "pass".to_string(),
            tls_enabled: true,
            tls_sni: "ipv6.example.com".to_string(),
            ..ProxyNode::default_with(ProxyProtocol::Trojan, "IPv6 Trojan", "2001:db8::1", 443)
        };

        let result = generate_output(
            &[tls_vmess, trojan],
            &TargetFormat::HiddifySafe,
            false,
            true,
        )
        .unwrap();
        let config: serde_json::Value = serde_json::from_str(&result.content).unwrap();
        let outbounds = config["outbounds"].as_array().unwrap();

        for outbound in outbounds
            .iter()
            .filter(|outbound| outbound["tag"] != "proxy")
        {
            assert!(outbound.get("domain_resolver").is_none());
        }
    }

    #[test]
    fn test_generate_hiddify_safe_rejects_when_no_tls_safe_nodes_exist() {
        let plain_vmess = ProxyNode {
            uuid: "33333333-3333-3333-3333-333333333333".to_string(),
            tls_enabled: false,
            ..ProxyNode::default_with(ProxyProtocol::Vmess, "Plain VMess", "plain.example.com", 80)
        };
        let hy2 = ProxyNode {
            password: "pass".to_string(),
            tls_enabled: true,
            tls_sni: "hy2.example.com".to_string(),
            ..ProxyNode::default_with(ProxyProtocol::Hysteria2, "HY2", "hy2.example.com", 1443)
        };

        let err = generate_output(
            &[plain_vmess, hy2],
            &TargetFormat::HiddifySafe,
            false,
            false,
        )
        .unwrap_err();

        assert_eq!(
            err,
            "No Hiddify-safe nodes found; only TLS-enabled non-Reality vmess, vless, and trojan are supported"
        );
    }

    #[test]
    fn test_generate_clash_format() {
        let node = ProxyNode {
            password: "pass".to_string(),
            tls_enabled: true,
            tls_sni: "sni.com".to_string(),
            ..ProxyNode::default_with(ProxyProtocol::Trojan, "Trojan", "server.com", 443)
        };

        let result = generate_output(&[node], &TargetFormat::Clash, true, true).unwrap();

        assert!(result.content.contains("proxies:"));
        assert!(result.content.contains("proxy-groups:"));
        assert!(result.content.contains("type: trojan"));
        assert_eq!(result.proxy_info.len(), 1);
        assert_eq!(result.outbounds_count, 1);
    }
}
