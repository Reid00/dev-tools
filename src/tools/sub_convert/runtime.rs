use super::{ConvertRequest, generator::TargetFormat};
#[cfg(test)]
use super::{
    gen_clash, gen_singbox,
    generator::{self, GenerateResult, ProxyInfo},
    parser, types,
};
#[cfg(test)]
use base64::Engine;
use reqwest::{Url, header};
#[cfg(test)]
use serde_json::{Value, json};
use std::net::{IpAddr, SocketAddr};
use tokio::net::lookup_host;
#[cfg(test)]
use urlencoding;

#[cfg(test)]
pub(crate) fn parse_vmess(url: &str) -> Result<Value, String> {
    let node = super::parse_vmess::parse_vmess(url)?;
    Ok(vmess_proxy_node_to_outbound(node))
}

#[cfg(test)]
pub(crate) fn vmess_proxy_node_to_outbound(node: types::ProxyNode) -> Value {
    let security = if node.method.is_empty() {
        "auto"
    } else {
        node.method.as_str()
    };

    let mut outbound = json!({
        "type": "vmess",
        "tag": node.name,
        "server": node.server,
        "server_port": node.port,
        "uuid": node.uuid,
        "alter_id": node.alter_id,
        "security": security,
        "network": "tcp"
    });

    match node.transport {
        types::TransportType::Ws => {
            let path = if node.transport_path.is_empty() {
                "/"
            } else {
                &node.transport_path
            };
            outbound["transport"] = json!({
                "type": "ws",
                "path": path,
                "headers": if node.transport_host.is_empty() {
                    json!({})
                } else {
                    json!({"Host": node.transport_host})
                }
            });
        }
        types::TransportType::Grpc => {
            outbound["transport"] = json!({
                "type": "grpc",
                "service_name": node.transport_service
            });
        }
        types::TransportType::Http => {
            let path = if node.transport_path.is_empty() {
                "/"
            } else {
                &node.transport_path
            };
            outbound["transport"] = json!({
                "type": "http",
                "path": path,
                "host": if node.transport_host.is_empty() {
                    json!([])
                } else {
                    json!([node.transport_host])
                }
            });
        }
        types::TransportType::Tcp => {}
    }

    if node.tls_enabled {
        outbound["tls"] = json!({
            "enabled": true,
            "server_name": node.tls_sni,
            "insecure": node.tls_insecure
        });
    }

    outbound
}

#[cfg(test)]
pub(crate) fn parse_vless(url: &str) -> Result<Value, String> {
    let node = super::parse_vless::parse_vless(url)?;
    Ok(vless_proxy_node_to_outbound(node))
}

#[cfg(test)]
pub(crate) fn vless_proxy_node_to_outbound(node: types::ProxyNode) -> Value {
    let mut outbound = json!({
        "type": "vless",
        "tag": node.name,
        "server": node.server,
        "server_port": node.port,
        "uuid": node.uuid
    });

    if !node.flow.is_empty() {
        outbound["flow"] = json!(node.flow);
    }

    match node.transport {
        types::TransportType::Ws => {
            let path = if node.transport_path.is_empty() {
                "/"
            } else {
                &node.transport_path
            };
            outbound["transport"] = json!({
                "type": "ws",
                "path": path,
                "headers": if node.transport_host.is_empty() {
                    json!({})
                } else {
                    json!({"Host": node.transport_host})
                }
            });
        }
        types::TransportType::Grpc => {
            outbound["transport"] = json!({
                "type": "grpc",
                "service_name": node.transport_service
            });
        }
        types::TransportType::Http => {
            let path = if node.transport_path.is_empty() {
                "/"
            } else {
                &node.transport_path
            };
            outbound["transport"] = json!({
                "type": "http",
                "path": path,
                "host": if node.transport_host.is_empty() {
                    json!([])
                } else {
                    json!([node.transport_host])
                }
            });
        }
        types::TransportType::Tcp => {}
    }

    if node.tls_enabled {
        let mut tls = json!({
            "enabled": true,
            "server_name": node.tls_sni,
            "insecure": node.tls_insecure
        });

        if !node.tls_fingerprint.is_empty() {
            tls["utls"] = json!({
                "enabled": true,
                "fingerprint": node.tls_fingerprint
            });
        }

        if !node.tls_alpn.is_empty() {
            tls["alpn"] = json!(node.tls_alpn);
        }

        if node.reality_enabled {
            let mut reality = json!({
                "enabled": true
            });
            if !node.reality_public_key.is_empty() {
                reality["public_key"] = json!(node.reality_public_key);
            }
            if !node.reality_short_id.is_empty() {
                reality["short_id"] = json!(node.reality_short_id);
            }
            tls["reality"] = reality;
        }

        outbound["tls"] = tls;
    }

    outbound
}

#[cfg(test)]
pub(crate) fn parse_trojan(url: &str) -> Result<Value, String> {
    let node = super::parse_trojan::parse_trojan(url)?;
    Ok(trojan_proxy_node_to_outbound(node))
}

#[cfg(test)]
pub(crate) fn trojan_proxy_node_to_outbound(node: types::ProxyNode) -> Value {
    let mut outbound = json!({
        "type": "trojan",
        "tag": node.name,
        "server": node.server,
        "server_port": node.port,
        "password": node.password,
        "network": "tcp"
    });

    match node.transport {
        types::TransportType::Ws => {
            let path = if node.transport_path.is_empty() {
                "/"
            } else {
                &node.transport_path
            };
            outbound["transport"] = json!({
                "type": "ws",
                "path": path,
                "headers": if node.transport_host.is_empty() {
                    json!({})
                } else {
                    json!({"Host": node.transport_host})
                }
            });
        }
        types::TransportType::Grpc => {
            outbound["transport"] = json!({
                "type": "grpc",
                "service_name": node.transport_service
            });
        }
        types::TransportType::Http => {
            let path = if node.transport_path.is_empty() {
                "/"
            } else {
                &node.transport_path
            };
            outbound["transport"] = json!({
                "type": "http",
                "path": path,
                "host": if node.transport_host.is_empty() {
                    json!([])
                } else {
                    json!([node.transport_host])
                }
            });
        }
        types::TransportType::Tcp => {}
    }

    let mut tls = json!({
        "enabled": true,
        "server_name": node.tls_sni
    });

    if !node.tls_fingerprint.is_empty() {
        tls["utls"] = json!({
            "enabled": true,
            "fingerprint": node.tls_fingerprint
        });
    }

    if !node.tls_alpn.is_empty() {
        tls["alpn"] = json!(node.tls_alpn);
    }

    if node.reality_enabled {
        let mut reality = json!({
            "enabled": true
        });
        if !node.reality_public_key.is_empty() {
            reality["public_key"] = json!(node.reality_public_key);
        }
        if !node.reality_short_id.is_empty() {
            reality["short_id"] = json!(node.reality_short_id);
        }
        tls["reality"] = reality;
    }

    outbound["tls"] = tls;

    outbound
}

#[cfg(test)]
pub(crate) fn parse_ss(url: &str) -> Result<Value, String> {
    let node = super::parse_ss::parse_ss(url)?;
    Ok(ss_proxy_node_to_outbound(node))
}

#[cfg(test)]
pub(crate) fn ss_proxy_node_to_outbound(node: types::ProxyNode) -> Value {
    let mut outbound = json!({
        "type": "shadowsocks",
        "tag": node.name,
        "server": node.server,
        "server_port": node.port,
        "method": node.method,
        "password": node.password
    });

    if !node.ss_plugin.is_empty() {
        outbound["plugin"] = json!(node.ss_plugin);
    }
    if !node.ss_plugin_opts.is_empty() {
        outbound["plugin_opts"] = json!(node.ss_plugin_opts);
    }

    outbound
}

#[cfg(test)]
pub(crate) fn parse_hysteria2(url: &str) -> Result<Value, String> {
    let node = super::parse_hysteria2::parse_hysteria2(url)?;
    Ok(hysteria2_proxy_node_to_outbound(node))
}

#[cfg(test)]
pub(crate) fn hysteria2_proxy_node_to_outbound(node: types::ProxyNode) -> Value {
    let mut outbound = json!({
        "type": "hysteria2",
        "tag": node.name,
        "server": node.server,
        "server_port": node.port,
        "password": node.password,
        "tls": {
            "enabled": true,
            "server_name": node.tls_sni,
            "insecure": node.tls_insecure
        }
    });

    if !node.tls_alpn.is_empty() {
        outbound["tls"]["alpn"] = json!(node.tls_alpn);
    }

    if !node.hy2_obfs_type.is_empty() || !node.hy2_obfs_password.is_empty() {
        let mut obfs = json!({});
        if !node.hy2_obfs_type.is_empty() {
            obfs["type"] = json!(node.hy2_obfs_type);
        }
        if !node.hy2_obfs_password.is_empty() {
            obfs["password"] = json!(node.hy2_obfs_password);
        }
        outbound["obfs"] = obfs;
    }

    if let Some(up_mbps) = node.hy2_up_mbps {
        outbound["up_mbps"] = json!(up_mbps);
    }

    if let Some(down_mbps) = node.hy2_down_mbps {
        outbound["down_mbps"] = json!(down_mbps);
    }

    outbound
}

#[cfg(test)]
pub(crate) fn parse_ssr(url: &str) -> Result<Value, String> {
    let node = super::parse_ssr::parse_ssr(url)?;
    Ok(ssr_proxy_node_to_outbound(node))
}

#[cfg(test)]
pub(crate) fn ssr_proxy_node_to_outbound(node: types::ProxyNode) -> Value {
    let mut outbound = json!({
        "type": "shadowsocksr",
        "tag": node.name,
        "server": node.server,
        "server_port": node.port,
        "method": node.method,
        "password": node.password
    });

    if !node.ssr_protocol.is_empty() {
        outbound["protocol"] = json!(node.ssr_protocol);
    }
    if !node.ssr_protocol_param.is_empty() {
        outbound["protocol_param"] = json!(node.ssr_protocol_param);
    }
    if !node.ssr_obfs.is_empty() {
        outbound["obfs"] = json!(node.ssr_obfs);
    }
    if !node.ssr_obfs_param.is_empty() {
        outbound["obfs_param"] = json!(node.ssr_obfs_param);
    }

    outbound
}

#[cfg(test)]
pub(crate) fn parse_anytls(url: &str) -> Result<Value, String> {
    let node = super::parse_anytls::parse_anytls(url)?;
    Ok(anytls_proxy_node_to_outbound(node))
}

#[cfg(test)]
pub(crate) fn anytls_proxy_node_to_outbound(node: types::ProxyNode) -> Value {
    let mut outbound = json!({
        "type": "anytls",
        "tag": node.name,
        "server": node.server,
        "server_port": node.port,
        "password": node.password,
        "network": "tcp",
        "tls": {
            "enabled": true,
            "server_name": node.tls_sni,
            "insecure": node.tls_insecure
        }
    });

    if !node.tls_fingerprint.is_empty() {
        outbound["tls"]["utls"] = json!({
            "enabled": true,
            "fingerprint": node.tls_fingerprint
        });
    }

    if !node.tls_alpn.is_empty() {
        outbound["tls"]["alpn"] = json!(node.tls_alpn);
    }

    if matches!(node.transport, types::TransportType::Ws) {
        let path = if node.transport_path.is_empty() {
            "/"
        } else {
            &node.transport_path
        };
        outbound["transport"] = json!({
            "type": "ws",
            "path": path,
            "headers": if node.transport_host.is_empty() {
                json!({})
            } else {
                json!({"Host": node.transport_host})
            }
        });
    }

    outbound
}

#[cfg(test)]
pub(crate) fn base64_decode(input: &str) -> Result<String, String> {
    let input: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    let input = input.replace('-', "+").replace('_', "/");
    let padding = (4 - input.len() % 4) % 4;
    let input = input + &"=".repeat(padding);

    base64::engine::general_purpose::STANDARD
        .decode(&input)
        .map(|bytes| String::from_utf8_lossy(&bytes).to_string())
        .map_err(|e| format!("Base64 decode error: {}", e))
}

#[cfg(test)]
pub(crate) fn build_proxy_outbound(url: &str) -> Result<Option<Value>, String> {
    let result = if url.starts_with("vmess://") {
        parse_vmess(url)
    } else if url.starts_with("vless://") {
        parse_vless(url)
    } else if url.starts_with("trojan://") {
        parse_trojan(url)
    } else if url.starts_with("ss://") {
        parse_ss(url)
    } else if url.starts_with("ssr://") {
        parse_ssr(url)
    } else if url.starts_with("hysteria2://") || url.starts_with("hy2://") {
        parse_hysteria2(url)
    } else if url.starts_with("anytls://") {
        parse_anytls(url)
    } else {
        return Ok(None);
    };

    result.map(Some)
}

#[cfg(test)]
pub(crate) fn collect_nodes_and_proxies(
    proxy_urls: &[String],
) -> Result<(Vec<types::ProxyNode>, Vec<ProxyInfo>), String> {
    let nodes = proxy_urls
        .iter()
        .map(|url| parser::parse_proxy_url(url))
        .collect::<Result<Vec<_>, _>>()?;

    let proxies = nodes
        .iter()
        .map(|node| ProxyInfo {
            name: node.name.clone(),
            server: node.server.clone(),
            port: node.port,
            protocol: node.protocol.protocol_str().to_string(),
        })
        .collect();

    Ok((nodes, proxies))
}

#[cfg(test)]
pub(crate) fn build_content(
    proxy_urls: &[String],
    format: &TargetFormat,
    include_direct: bool,
    include_dns: bool,
) -> Result<GenerateResult, String> {
    let nodes = proxy_urls
        .iter()
        .map(|url| parser::parse_proxy_url(url))
        .collect::<Result<Vec<_>, _>>()?;

    generator::generate_output(&nodes, format, include_direct, include_dns)
}

#[cfg(test)]
pub(crate) fn generate_subscription_content(proxy_urls: &[String]) -> Result<(String, Vec<ProxyInfo>), String> {
    let result = build_content(proxy_urls, &TargetFormat::Subscription, false, false)?;
    Ok((result.content, result.proxy_info))
}

#[cfg(test)]
pub(crate) fn generate_v2ray_subscription_content(
    proxy_urls: &[String],
) -> Result<(String, Vec<ProxyInfo>), String> {
    let result = build_content(proxy_urls, &TargetFormat::V2ray, false, false)?;
    Ok((result.content, result.proxy_info))
}

#[cfg(test)]
pub(crate) fn generate_singbox_config(
    proxy_urls: &[String],
    include_direct: bool,
    include_dns: bool,
) -> Result<(Value, Vec<ProxyInfo>), String> {
    let (nodes, proxies) = collect_nodes_and_proxies(proxy_urls)?;
    let config = gen_singbox::generate_singbox_config(&nodes, include_direct, include_dns, false)?;
    Ok((config, proxies))
}

#[cfg(test)]
pub(crate) fn generate_clash_yaml(
    proxy_urls: &[String],
    include_direct: bool,
    include_dns: bool,
) -> Result<(String, Vec<ProxyInfo>), String> {
    let (nodes, proxies) = collect_nodes_and_proxies(proxy_urls)?;
    let rendered = gen_clash::generate_clash_yaml(&nodes, include_direct, include_dns)?;
    Ok((rendered, proxies))
}

pub(crate) fn sanitize_source(source: &str) -> Result<String, String> {
    if source.trim().is_empty() {
        return Err("Subscription source cannot be empty".to_string());
    }

    if source.len() > 10000 {
        return Err("Subscription source is too long".to_string());
    }

    Ok(source.trim().to_string())
}

pub(crate) fn sanitize_raw_content(content: &str) -> Result<String, String> {
    if content.trim().is_empty() {
        return Err("Raw subscription content cannot be empty".to_string());
    }

    const MAX_SUBSCRIPTION_SIZE: usize = 2 * 1024 * 1024;
    if content.len() > MAX_SUBSCRIPTION_SIZE {
        return Err("Subscription content is too large".to_string());
    }

    Ok(content.trim().to_string())
}

pub(crate) fn is_forbidden_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_unique_local()
                || v6.is_unicast_link_local()
                || v6.to_ipv4_mapped().is_some_and(|mapped| is_forbidden_ip(IpAddr::V4(mapped)))
        }
    }
}

pub(crate) fn is_private_ip(host: &str) -> bool {
    let ip: IpAddr = match host.parse() {
        Ok(ip) => ip,
        Err(_) => return false,
    };

    is_forbidden_ip(ip)
}

fn validate_subscription_url_parsed(parsed: &Url) -> Result<(), String> {
    let scheme = parsed.scheme();
    if scheme != "http" && scheme != "https" {
        return Err("Subscription URL only supports http/https".to_string());
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| "Subscription URL host is required".to_string())?;
    let normalized_host = host.trim_matches(|c| c == '[' || c == ']').to_ascii_lowercase();

    if normalized_host == "localhost" || normalized_host.ends_with(".localhost") {
        return Err("localhost is not allowed".to_string());
    }

    if normalized_host.ends_with(".local") || normalized_host.ends_with(".internal") {
        return Err("Local/internal domains are not allowed".to_string());
    }

    if is_private_ip(&normalized_host) {
        return Err("Private IP addresses are not allowed".to_string());
    }

    Ok(())
}

pub(crate) fn validate_subscription_url(url: &str) -> Result<(), String> {
    let parsed = Url::parse(url).map_err(|e| format!("Invalid URL: {}", e))?;
    validate_subscription_url_parsed(&parsed)
}

async fn validate_subscription_target(url: &Url) -> Result<Vec<SocketAddr>, String> {
    validate_subscription_url_parsed(url)?;

    let host = url
        .host_str()
        .ok_or_else(|| "Subscription URL host is required".to_string())?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| "Subscription URL port is invalid".to_string())?;

    let addrs = lookup_host((host, port))
        .await
        .map_err(|e| format!("Failed to resolve subscription host: {}", e))?
        .collect::<Vec<SocketAddr>>();

    if addrs.is_empty() {
        return Err("Subscription host did not resolve to any address".to_string());
    }

    if addrs.iter().any(|addr| is_forbidden_ip(addr.ip())) {
        return Err("Subscription URL resolved to a private or local address".to_string());
    }

    Ok(addrs)
}

pub(crate) async fn fetch_subscription(url: &str, format: &TargetFormat) -> Result<String, String> {
    let mut current_url = Url::parse(url).map_err(|e| format!("Invalid URL: {}", e))?;

    let user_agent = match format {
        TargetFormat::Clash => "ClashforWindows/0.20.39",
        TargetFormat::Singbox | TargetFormat::HiddifySafe => "sing-box/1.10.0",
        TargetFormat::Subscription | TargetFormat::V2ray => "Hiddify/1.0.0",
    };

    for _ in 0..5 {
        let resolved_addrs = validate_subscription_target(&current_url).await?;
        let host = current_url
            .host_str()
            .ok_or_else(|| "Subscription URL host is required".to_string())?
            .to_string();

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .danger_accept_invalid_certs(false)
            .redirect(reqwest::redirect::Policy::none())
            .resolve_to_addrs(&host, &resolved_addrs)
            .build()
            .map_err(|e| format!("Failed to create client: {}", e))?;

        let resp = client
            .get(current_url.clone())
            .header("User-Agent", user_agent)
            .header("Accept", "*/*")
            .send()
            .await
            .map_err(|e| format!("Failed to fetch subscription: {}", e))?;

        if resp.status().is_redirection() {
            let location = resp
                .headers()
                .get(header::LOCATION)
                .ok_or_else(|| "Redirect response missing Location header".to_string())?
                .to_str()
                .map_err(|e| format!("Invalid redirect Location header: {}", e))?;
            current_url = current_url
                .join(location)
                .map_err(|e| format!("Invalid redirect URL: {}", e))?;
            continue;
        }

        if !resp.status().is_success() {
            return Err(format!("HTTP error: {}", resp.status()));
        }

        let bytes = resp
            .bytes()
            .await
            .map_err(|e| format!("Failed to read response: {}", e))?;

        const MAX_SUBSCRIPTION_SIZE: usize = 2 * 1024 * 1024;
        if bytes.len() > MAX_SUBSCRIPTION_SIZE {
            return Err("Subscription response is too large".to_string());
        }

        let text = String::from_utf8_lossy(&bytes).to_string();

        tracing::info!("Subscription response length: {} bytes", text.len());

        return Ok(text);
    }

    Err("Too many redirects while fetching subscription".to_string())
}

#[cfg(test)]
pub(crate) fn parse_subscription_content(content: &str) -> Result<Vec<String>, String> {
    let content = content.trim();

    tracing::info!(
        "Parsing subscription content, length: {} bytes",
        content.len()
    );

    if content.starts_with("vmess://")
        || content.starts_with("vless://")
        || content.starts_with("trojan://")
        || content.starts_with("ss://")
        || content.starts_with("ssr://")
        || content.starts_with("hysteria2://")
        || content.starts_with("hy2://")
        || content.starts_with("anytls://")
    {
        let urls: Vec<String> = content
            .lines()
            .map(|line| line.trim())
            .filter(|line| !line.is_empty())
            .filter(|line| {
                line.starts_with("vmess://")
                    || line.starts_with("vless://")
                    || line.starts_with("trojan://")
                    || line.starts_with("ss://")
                    || line.starts_with("ssr://")
                    || line.starts_with("hysteria2://")
                    || line.starts_with("hy2://")
                    || line.starts_with("anytls://")
            })
            .map(|s| s.to_string())
            .collect();
        tracing::info!("Found {} proxy URLs directly", urls.len());
        return Ok(urls);
    }

    if content.starts_with("port:")
        || content.starts_with("mixed-port:")
        || content.contains("proxies:")
    {
        tracing::info!("Detected Clash YAML format");
        return parse_clash_yaml(content);
    }

    let decoded = match base64_decode(content) {
        Ok(d) => {
            tracing::info!(
                "Successfully decoded base64, decoded length: {} bytes",
                d.len()
            );
            d
        }
        Err(e) => {
            tracing::info!("Base64 decode failed: {}, using raw content", e);
            content.to_string()
        }
    };

    if decoded.starts_with("port:")
        || decoded.starts_with("mixed-port:")
        || decoded.contains("proxies:")
    {
        tracing::info!("Decoded content is Clash YAML format");
        return parse_clash_yaml(&decoded);
    }

    let urls: Vec<String> = decoded
        .lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty())
        .filter(|line| {
            line.starts_with("vmess://")
                || line.starts_with("vless://")
                || line.starts_with("trojan://")
                || line.starts_with("ss://")
                || line.starts_with("ssr://")
                || line.starts_with("hysteria2://")
                || line.starts_with("hy2://")
                || line.starts_with("anytls://")
        })
        .map(|s| s.to_string())
        .collect();

    tracing::info!("Found {} proxy URLs", urls.len());
    Ok(urls)
}

#[cfg(test)]
pub(crate) fn parse_clash_yaml(content: &str) -> Result<Vec<String>, String> {
    let mut urls = Vec::new();

    let yaml: serde_yaml::Value =
        serde_yaml::from_str(content).map_err(|e| format!("Failed to parse YAML: {}", e))?;

    let proxies = yaml
        .get("proxies")
        .and_then(|p| p.as_sequence())
        .ok_or_else(|| "No proxies found in YAML".to_string())?;

    tracing::info!("Found {} proxies in Clash config", proxies.len());

    for proxy in proxies {
        if let Some(proxy_obj) = proxy.as_mapping() {
            if let Some(url) = clash_proxy_to_url(proxy_obj)? {
                urls.push(url);
            }
        }
    }

    Ok(urls)
}

#[cfg(test)]
pub(crate) fn clash_proxy_to_url(proxy: &serde_yaml::Mapping) -> Result<Option<String>, String> {
    let proxy_type = proxy
        .get("type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Clash proxy type is required".to_string())?;

    let name = proxy
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("proxy");

    match proxy_type {
        "ss" => {
            let server = proxy
                .get("server")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "Clash SS proxy server is required".to_string())?;
            let port = proxy
                .get("port")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| "Clash SS proxy port is required".to_string())?;
            let method = proxy
                .get("cipher")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "Clash SS proxy cipher is required".to_string())?;
            let password = proxy
                .get("password")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "Clash SS proxy password is required".to_string())?;

            let userinfo = format!("{}:{}", method, password);
            let encoded = base64::engine::general_purpose::STANDARD.encode(&userinfo);

            Ok(Some(format!(
                "ss://{}@{}:{}#{}",
                encoded,
                server,
                port,
                urlencoding::encode(name)
            )))
        }
        "ssr" => {
            let server = proxy
                .get("server")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "Clash SSR proxy server is required".to_string())?;
            let port = proxy
                .get("port")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| "Clash SSR proxy port is required".to_string())?;
            let method = proxy
                .get("cipher")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "Clash SSR proxy cipher is required".to_string())?;
            let password = proxy
                .get("password")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "Clash SSR proxy password is required".to_string())?;
            let protocol = proxy
                .get("protocol")
                .and_then(|v| v.as_str())
                .unwrap_or("origin");
            let protocol_param = proxy
                .get("protocol-param")
                .or_else(|| proxy.get("protocol_param"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let obfs = proxy
                .get("obfs")
                .and_then(|v| v.as_str())
                .unwrap_or("plain");
            let obfs_param = proxy
                .get("obfs-param")
                .or_else(|| proxy.get("obfs_param"))
                .and_then(|v| v.as_str())
                .unwrap_or("");

            let password_encoded = base64::engine::general_purpose::STANDARD.encode(password);
            let srchost = format!(
                "{}:{}:{}:{}:{}:{}/?obfsparam={}&protoparam={}&remarks={}",
                server,
                port,
                protocol,
                method,
                obfs,
                password_encoded,
                base64::engine::general_purpose::STANDARD.encode(obfs_param),
                base64::engine::general_purpose::STANDARD.encode(protocol_param),
                base64::engine::general_purpose::STANDARD.encode(name)
            );
            let encoded = base64::engine::general_purpose::STANDARD.encode(&srchost);
            Ok(Some(format!("ssr://{}", encoded)))
        }
        _ => {
            let server = match proxy.get("server").and_then(|v| v.as_str()) {
                Some(server) => server,
                None => return Ok(None),
            };
            let port = match proxy.get("port").and_then(|v| v.as_u64()) {
                Some(port) => port,
                None => return Ok(None),
            };

            match proxy_type {
                "vmess" => {
                    let uuid = match proxy.get("uuid").and_then(|v| v.as_str()) {
                        Some(uuid) => uuid,
                        None => return Ok(None),
                    };
                    let alter_id = proxy.get("alterId").and_then(|v| v.as_u64()).unwrap_or(0);
                    let network = proxy
                        .get("network")
                        .and_then(|v| v.as_str())
                        .unwrap_or("tcp");

                    let mut vmess_obj = json!({
                        "v": "2",
                        "ps": name,
                        "add": server,
                        "port": port.to_string(),
                        "id": uuid,
                        "aid": alter_id.to_string(),
                        "net": network,
                        "type": "none",
                        "host": "",
                        "path": "",
                        "tls": ""
                    });

                    if network == "ws" {
                        if let Some(ws_opts) = proxy.get("ws-opts").and_then(|v| v.as_mapping()) {
                            if let Some(path) = ws_opts.get("path").and_then(|v| v.as_str()) {
                                vmess_obj["path"] = json!(path);
                            }
                            if let Some(headers) = ws_opts.get("headers").and_then(|v| v.as_mapping()) {
                                if let Some(host) = headers.get("Host").and_then(|v| v.as_str()) {
                                    vmess_obj["host"] = json!(host);
                                }
                            }
                        }
                    }

                    if proxy.get("tls").and_then(|v| v.as_bool()).unwrap_or(false) {
                        vmess_obj["tls"] = json!("tls");
                        if let Some(sni) = proxy.get("servername").and_then(|v| v.as_str()) {
                            vmess_obj["host"] = json!(sni);
                        }
                    }

                    let vmess_json = serde_json::to_string(&vmess_obj)
                        .map_err(|e| format!("Failed to serialize Clash vmess proxy: {}", e))?;
                    let encoded = base64::engine::general_purpose::STANDARD.encode(&vmess_json);
                    Ok(Some(format!("vmess://{}", encoded)))
                }
                "vless" => {
                    let uuid = match proxy.get("uuid").and_then(|v| v.as_str()) {
                        Some(uuid) => uuid,
                        None => return Ok(None),
                    };
                    let flow = proxy.get("flow").and_then(|v| v.as_str()).unwrap_or("");

                    let mut url = format!("vless://{}@{}:{}?type=tcp", uuid, server, port);

                    if !flow.is_empty() {
                        url.push_str(&format!("&flow={}", flow));
                    }

                    if proxy.get("tls").and_then(|v| v.as_bool()).unwrap_or(false) {
                        url.push_str("&security=tls");
                        if let Some(sni) = proxy.get("servername").and_then(|v| v.as_str()) {
                            url.push_str(&format!("&sni={}", sni));
                        }
                    }

                    let network = proxy
                        .get("network")
                        .and_then(|v| v.as_str())
                        .unwrap_or("tcp");
                    if network == "ws" {
                        url.push_str("&type=ws");
                        if let Some(ws_opts) = proxy.get("ws-opts").and_then(|v| v.as_mapping()) {
                            if let Some(path) = ws_opts.get("path").and_then(|v| v.as_str()) {
                                url.push_str(&format!("&path={}", urlencoding::encode(path)));
                            }
                            if let Some(headers) = ws_opts.get("headers").and_then(|v| v.as_mapping()) {
                                if let Some(host) = headers.get("Host").and_then(|v| v.as_str()) {
                                    url.push_str(&format!("&host={}", urlencoding::encode(host)));
                                }
                            }
                        }
                    }

                    url.push_str(&format!("#{}", urlencoding::encode(name)));
                    Ok(Some(url))
                }
                "trojan" => {
                    let password = match proxy.get("password").and_then(|v| v.as_str()) {
                        Some(password) => password,
                        None => return Ok(None),
                    };

                    let mut url = format!("trojan://{}@{}:{}", password, server, port);
                    url.push_str("?security=tls");
                    if let Some(sni) = proxy
                        .get("sni")
                        .or_else(|| proxy.get("servername"))
                        .and_then(|v| v.as_str())
                    {
                        url.push_str(&format!("&sni={}", urlencoding::encode(sni)));
                    }
                    if let Some(fp) = proxy.get("client-fingerprint").and_then(|v| v.as_str()) {
                        if !fp.is_empty() {
                            url.push_str(&format!("&fp={}", urlencoding::encode(fp)));
                        }
                    }
                    if let Some(alpn) = proxy.get("alpn").and_then(|v| v.as_sequence()) {
                        let alpn_joined = alpn
                            .iter()
                            .filter_map(|v| v.as_str())
                            .filter(|s| !s.is_empty())
                            .collect::<Vec<_>>()
                            .join(",");
                        if !alpn_joined.is_empty() {
                            url.push_str(&format!("&alpn={}", urlencoding::encode(&alpn_joined)));
                        }
                    }

                    let network = proxy
                        .get("network")
                        .and_then(|v| v.as_str())
                        .unwrap_or("tcp");
                    if network == "ws" {
                        url.push_str("&type=ws");
                        if let Some(ws_opts) = proxy.get("ws-opts").and_then(|v| v.as_mapping()) {
                            if let Some(path) = ws_opts.get("path").and_then(|v| v.as_str()) {
                                url.push_str(&format!("&path={}", urlencoding::encode(path)));
                            }
                            if let Some(headers) = ws_opts.get("headers").and_then(|v| v.as_mapping()) {
                                if let Some(host) = headers.get("Host").and_then(|v| v.as_str()) {
                                    url.push_str(&format!("&host={}", urlencoding::encode(host)));
                                }
                            }
                        }
                    }

                    url.push_str(&format!("#{}", urlencoding::encode(name)));
                    Ok(Some(url))
                }
                "hysteria2" => {
                    let password = match proxy.get("password").and_then(|v| v.as_str()) {
                        Some(password) => password,
                        None => return Ok(None),
                    };

                    let mut url = format!(
                        "hysteria2://{}@{}:{}?",
                        urlencoding::encode(password),
                        server,
                        port
                    );

                    if let Some(sni) = proxy
                        .get("sni")
                        .or_else(|| proxy.get("servername"))
                        .and_then(|v| v.as_str())
                    {
                        if !sni.is_empty() {
                            url.push_str(&format!("sni={}&", urlencoding::encode(sni)));
                        }
                    }

                    if proxy
                        .get("skip-cert-verify")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false)
                    {
                        url.push_str("insecure=1&");
                    }

                    if let Some(alpn) = proxy.get("alpn").and_then(|v| v.as_sequence()) {
                        let alpn_joined = alpn
                            .iter()
                            .filter_map(|v| v.as_str())
                            .filter(|s| !s.is_empty())
                            .collect::<Vec<_>>()
                            .join(",");
                        if !alpn_joined.is_empty() {
                            url.push_str(&format!("alpn={}&", urlencoding::encode(&alpn_joined)));
                        }
                    }

                    if let Some(obfs) = proxy.get("obfs").and_then(|v| v.as_str()) {
                        if !obfs.is_empty() {
                            url.push_str(&format!("obfs={}&", urlencoding::encode(obfs)));
                        }
                    }
                    if let Some(obfs_password) = proxy.get("obfs-password").and_then(|v| v.as_str()) {
                        if !obfs_password.is_empty() {
                            url.push_str(&format!(
                                "obfs-password={}&",
                                urlencoding::encode(obfs_password)
                            ));
                        }
                    }

                    if let Some(up) = proxy.get("up").and_then(|v| v.as_u64()) {
                        url.push_str(&format!("up={}&", up));
                    }
                    if let Some(down) = proxy.get("down").and_then(|v| v.as_u64()) {
                        url.push_str(&format!("down={}&", down));
                    }

                    if url.ends_with('?') {
                        url.pop();
                    } else if url.ends_with('&') {
                        url.pop();
                    }
                    url.push_str(&format!("#{}", urlencoding::encode(name)));
                    Ok(Some(url))
                }
                "anytls" => {
                    let password = match proxy.get("password").and_then(|v| v.as_str()) {
                        Some(password) => password,
                        None => return Ok(None),
                    };

                    let mut url = format!(
                        "anytls://{}@{}:{}?",
                        urlencoding::encode(password),
                        server,
                        port
                    );

                    if let Some(sni) = proxy
                        .get("sni")
                        .or_else(|| proxy.get("servername"))
                        .and_then(|v| v.as_str())
                    {
                        if !sni.is_empty() {
                            url.push_str(&format!("sni={}&", urlencoding::encode(sni)));
                        }
                    }

                    if let Some(fp) = proxy.get("client-fingerprint").and_then(|v| v.as_str()) {
                        if !fp.is_empty() {
                            url.push_str(&format!("fp={}&", urlencoding::encode(fp)));
                        }
                    }

                    if let Some(alpn) = proxy.get("alpn").and_then(|v| v.as_sequence()) {
                        let alpn_joined = alpn
                            .iter()
                            .filter_map(|v| v.as_str())
                            .filter(|s| !s.is_empty())
                            .collect::<Vec<_>>()
                            .join(",");
                        if !alpn_joined.is_empty() {
                            url.push_str(&format!("alpn={}&", urlencoding::encode(&alpn_joined)));
                        }
                    }

                    if proxy
                        .get("skip-cert-verify")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false)
                    {
                        url.push_str("insecure=1&");
                    }

                    let network = proxy
                        .get("network")
                        .and_then(|v| v.as_str())
                        .unwrap_or("tcp");
                    if network == "ws" {
                        url.push_str("type=ws&");
                        if let Some(ws_opts) = proxy.get("ws-opts").and_then(|v| v.as_mapping()) {
                            if let Some(path) = ws_opts.get("path").and_then(|v| v.as_str()) {
                                url.push_str(&format!("path={}&", urlencoding::encode(path)));
                            }
                            if let Some(headers) = ws_opts.get("headers").and_then(|v| v.as_mapping()) {
                                if let Some(host) = headers.get("Host").and_then(|v| v.as_str()) {
                                    url.push_str(&format!("host={}&", urlencoding::encode(host)));
                                }
                            }
                        }
                    }

                    if url.ends_with('?') {
                        url.pop();
                    } else if url.ends_with('&') {
                        url.pop();
                    }
                    url.push_str(&format!("#{}", urlencoding::encode(name)));
                    Ok(Some(url))
                }
                _ => Ok(None),
            }
        }
    }
}

pub(crate) fn source_from_request(req: &ConvertRequest) -> Result<String, String> {
    if let Some(url) = req
        .subscription_url
        .as_ref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        validate_subscription_url(url)?;
        return Ok(url.to_string());
    }

    if let Some(content) = req
        .content
        .as_ref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        let raw = sanitize_raw_content(content)?;
        return Ok(format!("raw:{raw}"));
    }

    Err("Either subscription_url or content is required".to_string())
}

pub(crate) async fn parse_source_async(source: &str, format: &TargetFormat) -> Result<String, String> {
    let trimmed = source.trim();

    if let Some(raw) = trimmed.strip_prefix("raw:") {
        return sanitize_raw_content(raw);
    }

    let source = sanitize_source(trimmed)?;
    fetch_subscription(&source, format).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_subscription_url_rejects_localhost_like_hosts() {
        let err = validate_subscription_url("http://localhost/test").unwrap_err();
        assert!(err.contains("localhost"));

        let err = validate_subscription_url("http://service.internal/test").unwrap_err();
        assert!(err.contains("Local/internal"));
    }

    #[test]
    fn test_validate_subscription_url_rejects_private_ip_literals() {
        let err = validate_subscription_url("http://127.0.0.1/test").unwrap_err();
        assert!(err.contains("Private IP"));

        let err = validate_subscription_url("http://[::1]/test").unwrap_err();
        assert!(err.contains("Private IP"));

        let err = validate_subscription_url("http://[::ffff:127.0.0.1]/test").unwrap_err();
        assert!(err.contains("Private IP"));
    }

    #[test]
    fn test_is_forbidden_ip_rejects_private_and_loopback_addresses() {
        assert!(is_forbidden_ip("127.0.0.1".parse().unwrap()));
        assert!(is_forbidden_ip("10.0.0.8".parse().unwrap()));
        assert!(is_forbidden_ip("::1".parse().unwrap()));
        assert!(is_forbidden_ip("fe80::1".parse().unwrap()));
        assert!(is_forbidden_ip("::ffff:127.0.0.1".parse().unwrap()));
        assert!(!is_forbidden_ip("8.8.8.8".parse().unwrap()));
        assert!(!is_forbidden_ip("2001:4860:4860::8888".parse().unwrap()));
    }

    #[tokio::test]
    async fn test_fetch_subscription_rejects_localhost_before_request() {
        let err = fetch_subscription("http://localhost/test", &TargetFormat::Subscription)
            .await
            .unwrap_err();
        assert!(err.contains("localhost"));
    }
}

