use axum::{
    Json, Router,
    extract::{Path, Query},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::IntoResponse,
    routing::{get, post},
};
use base64::Engine;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};
use uuid::Uuid;

use urlencoding;

#[derive(Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum TargetFormat {
    Subscription,
    V2ray,
    Singbox,
    Clash,
}

impl Default for TargetFormat {
    fn default() -> Self {
        Self::Subscription
    }
}

impl TargetFormat {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Subscription => "subscription",
            Self::V2ray => "v2ray",
            Self::Singbox => "singbox",
            Self::Clash => "clash",
        }
    }

    fn content_type(&self) -> &'static str {
        match self {
            Self::Subscription | Self::V2ray => "text/plain; charset=utf-8",
            Self::Singbox => "application/json; charset=utf-8",
            Self::Clash => "text/yaml; charset=utf-8",
        }
    }

    fn code_class(&self) -> &'static str {
        match self {
            Self::Subscription | Self::V2ray => "language-text",
            Self::Singbox => "language-json",
            Self::Clash => "language-yaml",
        }
    }
}

#[derive(Deserialize)]
pub struct ConvertRequest {
    #[serde(default)]
    pub subscription_url: Option<String>,
    #[serde(default)]
    pub content: Option<String>,
    #[serde(default)]
    pub format: TargetFormat,
    #[serde(default)]
    pub preset: Option<String>,
    #[serde(default)]
    pub include_direct: bool,
    #[serde(default)]
    pub include_dns: bool,
}

#[derive(Serialize)]
pub struct ConvertResponse {
    pub success: bool,
    pub subscription_path: Option<String>,
    pub preview_content: Option<String>,
    pub content_type: Option<String>,
    pub code_class: Option<String>,
    pub format: Option<String>,
    pub proxies: Vec<ProxyInfo>,
    pub outbounds_count: usize,
    pub error: Option<String>,
}

#[derive(Serialize)]
pub struct ProxyInfo {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub protocol: String,
}

#[derive(Deserialize)]
pub struct SubscribeQuery {
    pub source: String,
    #[serde(default)]
    pub format: TargetFormat,
    #[serde(default)]
    pub include_direct: bool,
    #[serde(default)]
    pub include_dns: bool,
}

fn parse_vmess(url: &str) -> Result<Value, String> {
    let base64_part = url
        .strip_prefix("vmess://")
        .ok_or("Invalid vmess URL prefix")?;
    let base64_part = base64_part.replace('-', "+").replace('_', "/");
    let padding = (4 - base64_part.len() % 4) % 4;
    let base64_part = base64_part + &"=".repeat(padding);

    let json_str = base64_decode(&base64_part)?;
    let vmess: HashMap<String, Value> = serde_json::from_str(&json_str)
        .map_err(|e| format!("Failed to parse vmess JSON: {}", e))?;

    let add = vmess.get("add").and_then(|v| v.as_str()).unwrap_or("");
    let port = vmess
        .get("port")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(443);
    let id = vmess.get("id").and_then(|v| v.as_str()).unwrap_or("");
    let net = vmess.get("net").and_then(|v| v.as_str()).unwrap_or("tcp");
    let ps = vmess.get("ps").and_then(|v| v.as_str()).unwrap_or("vmess");
    let tls = vmess.get("tls").and_then(|v| v.as_str()).unwrap_or("");
    let host = vmess.get("host").and_then(|v| v.as_str()).unwrap_or("");
    let path = vmess.get("path").and_then(|v| v.as_str()).unwrap_or("/");
    let aid = vmess
        .get("aid")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0);

    let mut outbound = json!({
        "type": "vmess",
        "tag": ps,
        "server": add,
        "server_port": port,
        "uuid": id,
        "alter_id": aid,
        "security": "auto",
        "network": "tcp"
    });

    if net == "ws" {
        let transport = json!({
            "type": "ws",
            "path": path,
            "headers": if host.is_empty() { json!({}) } else { json!({"Host": host}) }
        });
        outbound["transport"] = transport;
    } else if net == "grpc" {
        let service_name = vmess.get("path").and_then(|v| v.as_str()).unwrap_or("");
        outbound["transport"] = json!({
            "type": "grpc",
            "service_name": service_name
        });
    } else if net == "http" {
        let transport = json!({
            "type": "http",
            "path": path,
            "host": if host.is_empty() { json!([]) } else { json!([host]) }
        });
        outbound["transport"] = transport;
    }

    if tls == "tls" {
        outbound["tls"] = json!({
            "enabled": true,
            "server_name": if host.is_empty() { json!(add) } else { json!(host) },
            "insecure": false
        });
    }

    Ok(outbound)
}

fn parse_vless(url: &str) -> Result<Value, String> {
    let url = url
        .strip_prefix("vless://")
        .ok_or("Invalid vless URL prefix")?;
    let parsed = Url::parse(&format!("vless://{}", url))
        .map_err(|e| format!("Failed to parse vless URL: {}", e))?;

    let uuid = parsed.username();
    let server = parsed.host_str().unwrap_or("");
    let port = parsed.port().unwrap_or(443);
    let name = parsed.fragment().unwrap_or("vless");

    let params: HashMap<String, String> = parsed
        .query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    let net = params.get("type").unwrap_or(&"tcp".to_string()).clone();
    let tls = params.get("security").unwrap_or(&"".to_string()).clone();
    let host = params.get("host").unwrap_or(&"".to_string()).clone();
    let path = params.get("path").unwrap_or(&"/".to_string()).clone();
    let flow = params.get("flow").unwrap_or(&"".to_string()).clone();
    let sni = params
        .get("sni")
        .or_else(|| params.get("servername"))
        .unwrap_or(&"".to_string())
        .clone();
    let fp = params
        .get("fp")
        .or_else(|| params.get("fingerprint"))
        .unwrap_or(&"".to_string())
        .clone();
    let alpn = params.get("alpn").unwrap_or(&"".to_string()).clone();

    let mut outbound = json!({
        "type": "vless",
        "tag": name,
        "server": server,
        "server_port": port,
        "uuid": uuid,
        "network": "tcp"
    });

    if !flow.is_empty() {
        outbound["flow"] = json!(flow);
    }

    if net == "ws" {
        outbound["transport"] = json!({
            "type": "ws",
            "path": path,
            "headers": if host.is_empty() { json!({}) } else { json!({"Host": host}) }
        });
    } else if net == "grpc" {
        let service_name = params.get("serviceName").unwrap_or(&"".to_string()).clone();
        outbound["transport"] = json!({
            "type": "grpc",
            "service_name": service_name
        });
    } else if net == "http" {
        outbound["transport"] = json!({
            "type": "http",
            "path": path,
            "host": if host.is_empty() { json!([]) } else { json!([host]) }
        });
    }

    if tls == "tls" || tls == "reality" {
        let mut tls_obj = json!({
            "enabled": true,
            "server_name": if !sni.is_empty() {
                json!(sni)
            } else if host.is_empty() {
                json!(server)
            } else {
                json!(host)
            }
        });

        if !fp.is_empty() {
            tls_obj["utls"] = json!({
                "enabled": true,
                "fingerprint": fp
            });
        }

        if !alpn.is_empty() {
            let alpn_list: Vec<&str> = alpn
                .split(',')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .collect();
            if !alpn_list.is_empty() {
                tls_obj["alpn"] = json!(alpn_list);
            }
        }

        if tls == "reality" {
            let pbk = params.get("pbk").unwrap_or(&"".to_string()).clone();
            let sid = params.get("sid").unwrap_or(&"".to_string()).clone();
            let mut reality = json!({
                "enabled": true
            });
            if !pbk.is_empty() {
                reality["public_key"] = json!(pbk);
            }
            if !sid.is_empty() {
                reality["short_id"] = json!(sid);
            }
            tls_obj["reality"] = reality;
        }

        outbound["tls"] = tls_obj;
    }

    Ok(outbound)
}

fn parse_trojan(url: &str) -> Result<Value, String> {
    let url = url
        .strip_prefix("trojan://")
        .ok_or("Invalid trojan URL prefix")?;

    let parsed = Url::parse(&format!("trojan://{}", url))
        .map_err(|e| format!("Failed to parse trojan URL: {}", e))?;

    let password = parsed.username();
    let server = parsed.host_str().unwrap_or("");
    let port = parsed.port().unwrap_or(443);
    let name = parsed.fragment().unwrap_or("trojan");

    let params: HashMap<String, String> = parsed
        .query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    let net = params.get("type").unwrap_or(&"tcp".to_string()).clone();
    let host = params.get("host").unwrap_or(&"".to_string()).clone();
    let path = params.get("path").unwrap_or(&"/".to_string()).clone();
    let sni = params
        .get("sni")
        .or_else(|| params.get("servername"))
        .unwrap_or(&"".to_string())
        .clone();
    let fp = params
        .get("fp")
        .or_else(|| params.get("fingerprint"))
        .unwrap_or(&"".to_string())
        .clone();
    let alpn = params.get("alpn").unwrap_or(&"".to_string()).clone();
    let security = params.get("security").unwrap_or(&"tls".to_string()).clone();

    let mut outbound = json!({
        "type": "trojan",
        "tag": name,
        "server": server,
        "server_port": port,
        "password": password,
        "network": "tcp"
    });

    if net == "ws" {
        outbound["transport"] = json!({
            "type": "ws",
            "path": path,
            "headers": if host.is_empty() { json!({}) } else { json!({"Host": host}) }
        });
    } else if net == "grpc" {
        let service_name = params.get("serviceName").unwrap_or(&"".to_string()).clone();
        outbound["transport"] = json!({
            "type": "grpc",
            "service_name": service_name
        });
    }

    let mut tls_obj = json!({
        "enabled": true,
        "server_name": if !sni.is_empty() {
            json!(sni)
        } else if host.is_empty() {
            json!(server)
        } else {
            json!(host)
        }
    });

    if !fp.is_empty() {
        tls_obj["utls"] = json!({
            "enabled": true,
            "fingerprint": fp
        });
    }

    if !alpn.is_empty() {
        let alpn_list: Vec<&str> = alpn
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect();
        if !alpn_list.is_empty() {
            tls_obj["alpn"] = json!(alpn_list);
        }
    }

    if security == "reality" {
        let pbk = params.get("pbk").unwrap_or(&"".to_string()).clone();
        let sid = params.get("sid").unwrap_or(&"".to_string()).clone();
        if !pbk.is_empty() {
            let mut reality = json!({
                "enabled": true,
                "public_key": pbk
            });
            if !sid.is_empty() {
                reality["short_id"] = json!(sid);
            }
            tls_obj["reality"] = reality;
        }
    }

    outbound["tls"] = tls_obj;

    Ok(outbound)
}

fn parse_ss(url: &str) -> Result<Value, String> {
    let url = url.strip_prefix("ss://").ok_or("Invalid ss URL prefix")?;

    let parsed = Url::parse(&format!("ss://{}", url))
        .map_err(|e| format!("Failed to parse ss URL: {}", e))?;

    let server = parsed.host_str().unwrap_or("");
    let port = parsed.port().unwrap_or(8388);
    let name = parsed.fragment().unwrap_or("ss");

    let userinfo = parsed.username();
    let userinfo_decoded = base64_decode(userinfo)?;
    let parts: Vec<&str> = userinfo_decoded.splitn(2, ':').collect();
    let (method, password) = if parts.len() == 2 {
        (parts[0], parts[1])
    } else {
        ("aes-128-gcm", parts[0])
    };

    Ok(json!({
        "type": "shadowsocks",
        "tag": name,
        "server": server,
        "server_port": port,
        "method": method,
        "password": password
    }))
}

fn parse_hysteria2(url: &str) -> Result<Value, String> {
    let raw = url
        .strip_prefix("hysteria2://")
        .or_else(|| url.strip_prefix("hy2://"))
        .ok_or("Invalid hysteria2 URL prefix")?;

    let parsed = Url::parse(&format!("hysteria2://{}", raw))
        .map_err(|e| format!("Failed to parse hysteria2 URL: {}", e))?;

    let password = parsed.username();
    let server = parsed.host_str().unwrap_or("");
    let port = parsed.port().unwrap_or(443);
    let name = parsed.fragment().unwrap_or("hysteria2");

    let params: HashMap<String, String> = parsed
        .query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    let sni = params
        .get("sni")
        .or_else(|| params.get("peer"))
        .cloned()
        .unwrap_or_default();
    let insecure = params
        .get("insecure")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    let mut outbound = json!({
        "type": "hysteria2",
        "tag": name,
        "server": server,
        "server_port": port,
        "password": password,
        "tls": {
            "enabled": true,
            "server_name": if sni.is_empty() { json!(server) } else { json!(sni) },
            "insecure": insecure
        }
    });

    let mut has_obfs = false;
    let mut obfs = json!({});

    if let Some(obfs_type) = params.get("obfs").filter(|v| !v.is_empty()) {
        obfs["type"] = json!(obfs_type);
        has_obfs = true;
    }

    if let Some(obfs_password) = params
        .get("obfs-password")
        .or_else(|| params.get("obfs_password"))
        .filter(|v| !v.is_empty())
    {
        obfs["password"] = json!(obfs_password);
        has_obfs = true;
    }

    if has_obfs {
        outbound["obfs"] = obfs;
    }

    if let Some(alpn) = params.get("alpn").filter(|v| !v.is_empty()) {
        let alpn_list: Vec<&str> = alpn
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect();
        if !alpn_list.is_empty() {
            outbound["tls"]["alpn"] = json!(alpn_list);
        }
    }

    if let Some(up_mbps) = params
        .get("upmbps")
        .or_else(|| params.get("up"))
        .and_then(|v| v.parse::<u64>().ok())
    {
        outbound["up_mbps"] = json!(up_mbps);
    }

    if let Some(down_mbps) = params
        .get("downmbps")
        .or_else(|| params.get("down"))
        .and_then(|v| v.parse::<u64>().ok())
    {
        outbound["down_mbps"] = json!(down_mbps);
    }

    Ok(outbound)
}

fn parse_ssr(url: &str) -> Result<Value, String> {
    let base64_part = url.strip_prefix("ssr://").ok_or("Invalid ssr URL prefix")?;
    let decoded = base64_decode(base64_part)?;
    let parts: Vec<&str> = decoded.splitn(2, '/').collect();
    let server_parts: Vec<&str> = parts[0].split(':').collect();

    if server_parts.len() < 6 {
        return Err("Invalid SSR format".to_string());
    }

    let server = server_parts[0];
    let port = server_parts[1].parse::<u16>().unwrap_or(8388);
    let method = server_parts[3];
    let password = base64_decode(server_parts[5])?;

    Ok(json!({
        "type": "shadowsocks",
        "tag": "ssr",
        "server": server,
        "server_port": port,
        "method": method,
        "password": password
    }))
}

fn parse_anytls(url: &str) -> Result<Value, String> {
    let raw = url
        .strip_prefix("anytls://")
        .ok_or("Invalid anytls URL prefix")?;

    let parsed = Url::parse(&format!("anytls://{}", raw))
        .map_err(|e| format!("Failed to parse anytls URL: {}", e))?;

    let password = parsed.username();
    let server = parsed.host_str().unwrap_or("");
    let port = parsed.port().unwrap_or(443);
    let name = parsed.fragment().unwrap_or("anytls");

    let params: HashMap<String, String> = parsed
        .query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    let net = params.get("type").map(|s| s.as_str()).unwrap_or("tcp");
    let host = params.get("host").map(|s| s.as_str()).unwrap_or("");
    let path = params.get("path").map(|s| s.as_str()).unwrap_or("/");
    let sni = params
        .get("sni")
        .or_else(|| params.get("servername"))
        .map(|s| s.as_str())
        .unwrap_or("");
    let fp = params
        .get("fp")
        .or_else(|| params.get("fingerprint"))
        .map(|s| s.as_str())
        .unwrap_or("");
    let alpn = params.get("alpn").map(|s| s.as_str()).unwrap_or("");
    let insecure = params
        .get("insecure")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    let mut outbound = json!({
        "type": "anytls",
        "tag": name,
        "server": server,
        "server_port": port,
        "password": password,
        "network": "tcp",
        "tls": {
            "enabled": true,
            "server_name": if !sni.is_empty() {
                json!(sni)
            } else if host.is_empty() {
                json!(server)
            } else {
                json!(host)
            },
            "insecure": insecure
        }
    });

    if !fp.is_empty() {
        outbound["tls"]["utls"] = json!({
            "enabled": true,
            "fingerprint": fp
        });
    }

    if !alpn.is_empty() {
        let alpn_list: Vec<&str> = alpn
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect();
        if !alpn_list.is_empty() {
            outbound["tls"]["alpn"] = json!(alpn_list);
        }
    }

    if net == "ws" {
        outbound["transport"] = json!({
            "type": "ws",
            "path": path,
            "headers": if host.is_empty() { json!({}) } else { json!({"Host": host}) }
        });
    }

    Ok(outbound)
}

fn base64_decode(input: &str) -> Result<String, String> {
    let input: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    let input = input.replace('-', "+").replace('_', "/");
    let padding = (4 - input.len() % 4) % 4;
    let input = input + &"=".repeat(padding);

    base64::engine::general_purpose::STANDARD
        .decode(&input)
        .map(|bytes| String::from_utf8_lossy(&bytes).to_string())
        .map_err(|e| format!("Base64 decode error: {}", e))
}

fn build_proxy_outbound(url: &str) -> Option<Value> {
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
        return None;
    };

    result.ok()
}

fn collect_outbounds_and_proxies(proxy_urls: &[String]) -> (Vec<Value>, Vec<ProxyInfo>) {
    let mut outbounds = vec![];
    let mut proxies = vec![];

    for url in proxy_urls {
        if let Some(outbound) = build_proxy_outbound(url) {
            let name = outbound["tag"].as_str().unwrap_or("proxy").to_string();
            let server = outbound["server"].as_str().unwrap_or("").to_string();
            let port = outbound["server_port"].as_u64().unwrap_or(443) as u16;
            let protocol = outbound["type"].as_str().unwrap_or("").to_string();

            proxies.push(ProxyInfo {
                name,
                server,
                port,
                protocol,
            });

            outbounds.push(outbound);
        }
    }

    (outbounds, proxies)
}

fn generate_singbox_config(
    proxy_urls: &[String],
    include_direct: bool,
    include_dns: bool,
) -> (Value, Vec<ProxyInfo>) {
    let (proxy_outbounds, proxies) = collect_outbounds_and_proxies(proxy_urls);

    let proxy_tags: Vec<String> = proxy_outbounds
        .iter()
        .filter_map(|o| o["tag"].as_str().map(|s| s.to_string()))
        .collect();

    let mut selector_outbounds = vec!["auto".to_string()];
    if include_direct {
        selector_outbounds.push("direct".to_string());
    }
    selector_outbounds.extend(proxy_tags.clone());

    let selector = json!({
        "type": "selector",
        "tag": "proxy",
        "outbounds": selector_outbounds
    });

    let urltest = json!({
        "type": "urltest",
        "tag": "auto",
        "outbounds": proxy_tags,
        "url": "https://www.gstatic.com/generate_204",
        "interval": "3m",
        "tolerance": 50
    });

    let mut config = json!({
        "log": {
            "level": "info",
            "timestamp": true
        },
        "inbounds": [
            {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "127.0.0.1",
                "listen_port": 10808,
                "sniff": true,
                "sniff_override_destination": true
            }
        ],
        "outbounds": vec![selector, urltest]
    });

    let mut all_outbounds = config["outbounds"].as_array_mut().unwrap().clone();
    all_outbounds.extend(proxy_outbounds);

    if include_direct {
        all_outbounds.push(json!({
            "type": "direct",
            "tag": "direct"
        }));
    }

    config["outbounds"] = json!(all_outbounds);

    if include_dns {
        config["dns"] = json!({
            "servers": [
                {"tag": "google", "type": "tls", "server": "8.8.8.8"},
                {"tag": "local", "type": "udp", "server": "223.5.5.5"}
            ],
            "rules": [
                {"query_type": ["A", "AAAA"], "server": "google"}
            ],
            "strategy": "ipv4_only"
        });
    }

    let mut route_rules = vec![];

    if include_dns {
        route_rules.push(json!({"protocol": "dns", "action": "hijack-dns"}));
    }

    if include_direct {
        route_rules.push(json!({"ip_is_private": true, "action": "route", "outbound": "direct"}));
    }

    let mut route = json!({
        "rules": route_rules,
        "auto_detect_interface": true,
        "final": "proxy"
    });

    if include_dns {
        route["default_domain_resolver"] = json!("local");
    }

    config["route"] = route;

    (config, proxies)
}

fn generate_clash_yaml(
    proxy_urls: &[String],
    include_direct: bool,
    include_dns: bool,
) -> Result<(String, Vec<ProxyInfo>), String> {
    let (proxy_outbounds, proxies) = collect_outbounds_and_proxies(proxy_urls);

    let mut clash_proxies: Vec<serde_yaml::Value> = vec![];
    let mut proxy_names: Vec<String> = vec![];

    for outbound in &proxy_outbounds {
        let name = outbound["tag"].as_str().unwrap_or("proxy").to_string();
        proxy_names.push(name.clone());

        let proxy_type = outbound["type"].as_str().unwrap_or("");
        let server = outbound["server"].as_str().unwrap_or("");
        let port = outbound["server_port"].as_u64().unwrap_or(443);

        let mut node = serde_yaml::Mapping::new();
        node.insert(
            serde_yaml::Value::String("name".to_string()),
            serde_yaml::Value::String(name),
        );
        let clash_type = match proxy_type {
            "shadowsocks" => "ss",
            other => other,
        };
        node.insert(
            serde_yaml::Value::String("type".to_string()),
            serde_yaml::Value::String(clash_type.to_string()),
        );
        node.insert(
            serde_yaml::Value::String("server".to_string()),
            serde_yaml::Value::String(server.to_string()),
        );
        node.insert(
            serde_yaml::Value::String("port".to_string()),
            serde_yaml::Value::Number(serde_yaml::Number::from(port)),
        );

        match proxy_type {
            "vmess" | "vless" => {
                let uuid = outbound["uuid"].as_str().unwrap_or("");
                node.insert(
                    serde_yaml::Value::String("uuid".to_string()),
                    serde_yaml::Value::String(uuid.to_string()),
                );
                if proxy_type == "vmess" {
                    node.insert(
                        serde_yaml::Value::String("alterId".to_string()),
                        serde_yaml::Value::Number(serde_yaml::Number::from(
                            outbound["alter_id"].as_u64().unwrap_or(0),
                        )),
                    );
                    node.insert(
                        serde_yaml::Value::String("cipher".to_string()),
                        serde_yaml::Value::String("auto".to_string()),
                    );
                } else {
                    node.insert(
                        serde_yaml::Value::String("cipher".to_string()),
                        serde_yaml::Value::String("none".to_string()),
                    );
                    if let Some(flow) = outbound["flow"].as_str() {
                        if !flow.is_empty() {
                            node.insert(
                                serde_yaml::Value::String("flow".to_string()),
                                serde_yaml::Value::String(flow.to_string()),
                            );
                        }
                    }
                }
            }
            "trojan" => {
                let password = outbound["password"].as_str().unwrap_or("");
                node.insert(
                    serde_yaml::Value::String("password".to_string()),
                    serde_yaml::Value::String(password.to_string()),
                );
            }
            "shadowsocks" => {
                let method = outbound["method"].as_str().unwrap_or("aes-128-gcm");
                let password = outbound["password"].as_str().unwrap_or("");
                node.insert(
                    serde_yaml::Value::String("cipher".to_string()),
                    serde_yaml::Value::String(method.to_string()),
                );
                node.insert(
                    serde_yaml::Value::String("password".to_string()),
                    serde_yaml::Value::String(password.to_string()),
                );
            }
            "hysteria2" => {
                let password = outbound["password"].as_str().unwrap_or("");
                node.insert(
                    serde_yaml::Value::String("password".to_string()),
                    serde_yaml::Value::String(password.to_string()),
                );

                if let Some(up) = outbound["up_mbps"].as_u64() {
                    node.insert(
                        serde_yaml::Value::String("up".to_string()),
                        serde_yaml::Value::Number(serde_yaml::Number::from(up)),
                    );
                }
                if let Some(down) = outbound["down_mbps"].as_u64() {
                    node.insert(
                        serde_yaml::Value::String("down".to_string()),
                        serde_yaml::Value::Number(serde_yaml::Number::from(down)),
                    );
                }

                if let Some(obfs) = outbound["obfs"].as_object() {
                    if let Some(obfs_type) = obfs.get("type").and_then(|v| v.as_str()) {
                        if !obfs_type.is_empty() {
                            node.insert(
                                serde_yaml::Value::String("obfs".to_string()),
                                serde_yaml::Value::String(obfs_type.to_string()),
                            );
                        }
                    }
                    if let Some(obfs_password) = obfs.get("password").and_then(|v| v.as_str()) {
                        if !obfs_password.is_empty() {
                            node.insert(
                                serde_yaml::Value::String("obfs-password".to_string()),
                                serde_yaml::Value::String(obfs_password.to_string()),
                            );
                        }
                    }
                }
            }
            "anytls" => {
                let password = outbound["password"].as_str().unwrap_or("");
                node.insert(
                    serde_yaml::Value::String("password".to_string()),
                    serde_yaml::Value::String(password.to_string()),
                );
            }
            _ => {}
        }

        if let Some(tls) = outbound["tls"].as_object() {
            if tls.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false) {
                node.insert(
                    serde_yaml::Value::String("tls".to_string()),
                    serde_yaml::Value::Bool(true),
                );

                if let Some(servername) = tls.get("server_name").and_then(|v| v.as_str()) {
                    if !servername.is_empty() {
                        node.insert(
                            serde_yaml::Value::String("servername".to_string()),
                            serde_yaml::Value::String(servername.to_string()),
                        );
                    }
                }

                if tls.get("insecure").and_then(|v| v.as_bool()).unwrap_or(false) {
                    node.insert(
                        serde_yaml::Value::String("skip-cert-verify".to_string()),
                        serde_yaml::Value::Bool(true),
                    );
                }

                if let Some(fingerprint) = tls
                    .get("utls")
                    .and_then(|v| v.get("fingerprint"))
                    .and_then(|v| v.as_str())
                {
                    if !fingerprint.is_empty() {
                        node.insert(
                            serde_yaml::Value::String("client-fingerprint".to_string()),
                            serde_yaml::Value::String(fingerprint.to_string()),
                        );
                    }
                }

                if let Some(alpn) = tls.get("alpn").and_then(|v| v.as_array()) {
                    let alpn_values: Vec<serde_yaml::Value> = alpn
                        .iter()
                        .filter_map(|v| v.as_str())
                        .map(|s| serde_yaml::Value::String(s.to_string()))
                        .collect();
                    if !alpn_values.is_empty() {
                        node.insert(
                            serde_yaml::Value::String("alpn".to_string()),
                            serde_yaml::Value::Sequence(alpn_values),
                        );
                    }
                }
            }
        }

        if let Some(transport) = outbound["transport"].as_object() {
            let network = transport
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("tcp");

            if network != "tcp" {
                node.insert(
                    serde_yaml::Value::String("network".to_string()),
                    serde_yaml::Value::String(network.to_string()),
                );
            }

            if network == "ws" {
                let mut ws_opts = serde_yaml::Mapping::new();
                let path = transport.get("path").and_then(|v| v.as_str()).unwrap_or("/");
                ws_opts.insert(
                    serde_yaml::Value::String("path".to_string()),
                    serde_yaml::Value::String(path.to_string()),
                );

                let host = transport
                    .get("headers")
                    .and_then(|v| v.get("Host"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if !host.is_empty() {
                    let mut headers = serde_yaml::Mapping::new();
                    headers.insert(
                        serde_yaml::Value::String("Host".to_string()),
                        serde_yaml::Value::String(host.to_string()),
                    );
                    ws_opts.insert(
                        serde_yaml::Value::String("headers".to_string()),
                        serde_yaml::Value::Mapping(headers),
                    );
                }

                node.insert(
                    serde_yaml::Value::String("ws-opts".to_string()),
                    serde_yaml::Value::Mapping(ws_opts),
                );
            }

            if network == "grpc" {
                if let Some(service_name) = transport.get("service_name").and_then(|v| v.as_str()) {
                    if !service_name.is_empty() {
                        let mut grpc_opts = serde_yaml::Mapping::new();
                        grpc_opts.insert(
                            serde_yaml::Value::String("grpc-service-name".to_string()),
                            serde_yaml::Value::String(service_name.to_string()),
                        );
                        node.insert(
                            serde_yaml::Value::String("grpc-opts".to_string()),
                            serde_yaml::Value::Mapping(grpc_opts),
                        );
                    }
                }
            }
        }

        clash_proxies.push(serde_yaml::Value::Mapping(node));
    }

    let mut proxy_group_outbounds = vec![serde_yaml::Value::String("auto".to_string())];
    if include_direct {
        proxy_group_outbounds.push(serde_yaml::Value::String("DIRECT".to_string()));
    }
    proxy_group_outbounds.extend(
        proxy_names
            .iter()
            .map(|name| serde_yaml::Value::String(name.clone())),
    );

    let mut groups = vec![];

    let mut select_group = serde_yaml::Mapping::new();
    select_group.insert(
        serde_yaml::Value::String("name".to_string()),
        serde_yaml::Value::String("Proxy".to_string()),
    );
    select_group.insert(
        serde_yaml::Value::String("type".to_string()),
        serde_yaml::Value::String("select".to_string()),
    );
    select_group.insert(
        serde_yaml::Value::String("proxies".to_string()),
        serde_yaml::Value::Sequence(proxy_group_outbounds),
    );
    groups.push(serde_yaml::Value::Mapping(select_group));

    let mut auto_group = serde_yaml::Mapping::new();
    auto_group.insert(
        serde_yaml::Value::String("name".to_string()),
        serde_yaml::Value::String("auto".to_string()),
    );
    auto_group.insert(
        serde_yaml::Value::String("type".to_string()),
        serde_yaml::Value::String("url-test".to_string()),
    );
    auto_group.insert(
        serde_yaml::Value::String("url".to_string()),
        serde_yaml::Value::String("https://www.gstatic.com/generate_204".to_string()),
    );
    auto_group.insert(
        serde_yaml::Value::String("interval".to_string()),
        serde_yaml::Value::Number(serde_yaml::Number::from(180)),
    );
    auto_group.insert(
        serde_yaml::Value::String("tolerance".to_string()),
        serde_yaml::Value::Number(serde_yaml::Number::from(50)),
    );
    auto_group.insert(
        serde_yaml::Value::String("proxies".to_string()),
        serde_yaml::Value::Sequence(
            proxy_names
                .iter()
                .map(|name| serde_yaml::Value::String(name.clone()))
                .collect(),
        ),
    );
    groups.push(serde_yaml::Value::Mapping(auto_group));

    let mut rules = vec![];
    if include_dns {
        rules.push(serde_yaml::Value::String(
            "PROCESS-NAME,systemd-resolved,DIRECT".to_string(),
        ));
    }
    if include_direct {
        rules.push(serde_yaml::Value::String(
            "GEOIP,LAN,DIRECT,no-resolve".to_string(),
        ));
    }
    rules.push(serde_yaml::Value::String("MATCH,Proxy".to_string()));

    let mut root = serde_yaml::Mapping::new();
    root.insert(
        serde_yaml::Value::String("mixed-port".to_string()),
        serde_yaml::Value::Number(serde_yaml::Number::from(7890)),
    );
    root.insert(
        serde_yaml::Value::String("allow-lan".to_string()),
        serde_yaml::Value::Bool(true),
    );
    root.insert(
        serde_yaml::Value::String("mode".to_string()),
        serde_yaml::Value::String("rule".to_string()),
    );
    root.insert(
        serde_yaml::Value::String("log-level".to_string()),
        serde_yaml::Value::String("info".to_string()),
    );
    root.insert(
        serde_yaml::Value::String("proxies".to_string()),
        serde_yaml::Value::Sequence(clash_proxies),
    );
    root.insert(
        serde_yaml::Value::String("proxy-groups".to_string()),
        serde_yaml::Value::Sequence(groups),
    );
    root.insert(
        serde_yaml::Value::String("rules".to_string()),
        serde_yaml::Value::Sequence(rules),
    );

    if include_dns {
        let mut dns = serde_yaml::Mapping::new();
        dns.insert(
            serde_yaml::Value::String("enable".to_string()),
            serde_yaml::Value::Bool(true),
        );
        dns.insert(
            serde_yaml::Value::String("ipv6".to_string()),
            serde_yaml::Value::Bool(false),
        );
        dns.insert(
            serde_yaml::Value::String("enhanced-mode".to_string()),
            serde_yaml::Value::String("fake-ip".to_string()),
        );
        dns.insert(
            serde_yaml::Value::String("nameserver".to_string()),
            serde_yaml::Value::Sequence(vec![
                serde_yaml::Value::String("https://8.8.8.8/dns-query".to_string()),
                serde_yaml::Value::String("https://223.5.5.5/dns-query".to_string()),
            ]),
        );
        root.insert(
            serde_yaml::Value::String("dns".to_string()),
            serde_yaml::Value::Mapping(dns),
        );
    }

    serde_yaml::to_string(&root)
        .map(|s| (s, proxies))
        .map_err(|e| format!("Failed to serialize clash yaml: {}", e))
}


fn generate_v2ray_subscription_content(proxy_urls: &[String]) -> (String, Vec<ProxyInfo>) {
    let (_, proxies) = collect_outbounds_and_proxies(proxy_urls);
    let joined = proxy_urls.join("\n");
    (joined, proxies)
}

fn generate_subscription_content(proxy_urls: &[String]) -> (String, Vec<ProxyInfo>) {
    let (_, proxies) = collect_outbounds_and_proxies(proxy_urls);
    let joined = proxy_urls.join("\n");
    let content = base64::engine::general_purpose::STANDARD.encode(joined);
    (content, proxies)
}

fn build_content(
    proxy_urls: &[String],
    format: &TargetFormat,
    include_direct: bool,
    include_dns: bool,
) -> Result<(String, Vec<ProxyInfo>, usize), String> {
    match format {
        TargetFormat::Subscription => {
            let (content, proxies) = generate_subscription_content(proxy_urls);
            let outbounds_count = proxies.len();
            Ok((content, proxies, outbounds_count))
        }
        TargetFormat::V2ray => {
            let (content, proxies) = generate_v2ray_subscription_content(proxy_urls);
            let outbounds_count = proxies.len();
            Ok((content, proxies, outbounds_count))
        }
        TargetFormat::Singbox => {
            let (config, proxies) =
                generate_singbox_config(proxy_urls, include_direct, include_dns);
            let outbounds_count = config["outbounds"].as_array().map(|a| a.len()).unwrap_or(0);
            let content = serde_json::to_string_pretty(&config)
                .map_err(|e| format!("Failed to serialize sing-box config: {}", e))?;
            Ok((content, proxies, outbounds_count))
        }
        TargetFormat::Clash => {
            let (content, proxies) = generate_clash_yaml(proxy_urls, include_direct, include_dns)?;
            let outbounds_count = proxies.len();
            Ok((content, proxies, outbounds_count))
        }
    }
}

fn sanitize_source(source: &str) -> Result<String, String> {
    if source.trim().is_empty() {
        return Err("Subscription source cannot be empty".to_string());
    }

    if source.len() > 10000 {
        return Err("Subscription source is too long".to_string());
    }

    Ok(source.trim().to_string())
}

fn is_private_ip(host: &str) -> bool {
    use std::net::IpAddr;

    let ip: IpAddr = match host.parse() {
        Ok(ip) => ip,
        Err(_) => return false,
    };

    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
        }
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified() || v6.is_unique_local(),
    }
}

fn validate_subscription_url(url: &str) -> Result<(), String> {
    let parsed = Url::parse(url).map_err(|e| format!("Invalid URL: {}", e))?;

    let scheme = parsed.scheme();
    if scheme != "http" && scheme != "https" {
        return Err("Subscription URL only supports http/https".to_string());
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| "Subscription URL host is required".to_string())?
        .to_ascii_lowercase();

    if host == "localhost" || host.ends_with(".localhost") {
        return Err("localhost is not allowed".to_string());
    }

    if host.ends_with(".local") || host.ends_with(".internal") {
        return Err("Local/internal domains are not allowed".to_string());
    }

    if is_private_ip(&host) {
        return Err("Private IP addresses are not allowed".to_string());
    }

    Ok(())
}

async fn fetch_subscription(url: &str, format: &TargetFormat) -> Result<String, String> {
    validate_subscription_url(url)?;

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .danger_accept_invalid_certs(false)
        .build()
        .map_err(|e| format!("Failed to create client: {}", e))?;

    let user_agent = match format {
        TargetFormat::Clash => "ClashforWindows/0.20.39",
        TargetFormat::Singbox => "sing-box/1.10.0",
        TargetFormat::Subscription | TargetFormat::V2ray => "clash.meta",
    };

    let resp = client
        .get(url)
        .header("User-Agent", user_agent)
        .header("Accept", "*/*")
        .send()
        .await
        .map_err(|e| format!("Failed to fetch subscription: {}", e))?;

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
    tracing::info!(
        "First 200 chars: {:?}",
        &text.chars().take(200).collect::<String>()
    );

    Ok(text)
}

fn parse_subscription_content(content: &str) -> Vec<String> {
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
        return urls;
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
    urls
}

fn parse_clash_yaml(content: &str) -> Vec<String> {
    let mut urls = Vec::new();

    let yaml: serde_yaml::Value = match serde_yaml::from_str(content) {
        Ok(y) => y,
        Err(e) => {
            tracing::error!("Failed to parse YAML: {}", e);
            return urls;
        }
    };

    let proxies = match yaml.get("proxies").and_then(|p| p.as_sequence()) {
        Some(p) => p,
        None => {
            tracing::error!("No proxies found in YAML");
            return urls;
        }
    };

    tracing::info!("Found {} proxies in Clash config", proxies.len());

    for proxy in proxies {
        if let Some(proxy_obj) = proxy.as_mapping() {
            if let Some(url) = clash_proxy_to_url(proxy_obj) {
                urls.push(url);
            }
        }
    }

    urls
}

fn clash_proxy_to_url(proxy: &serde_yaml::Mapping) -> Option<String> {
    let proxy_type = proxy.get("type").and_then(|v| v.as_str())?;

    let name = proxy
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("proxy");
    let server = proxy.get("server").and_then(|v| v.as_str())?;
    let port = proxy.get("port").and_then(|v| v.as_u64())?;

    match proxy_type {
        "vmess" => {
            let uuid = proxy.get("uuid").and_then(|v| v.as_str())?;
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

            let vmess_json = serde_json::to_string(&vmess_obj).ok()?;
            let encoded = base64::engine::general_purpose::STANDARD.encode(&vmess_json);
            Some(format!("vmess://{}", encoded))
        }
        "vless" => {
            let uuid = proxy.get("uuid").and_then(|v| v.as_str())?;
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
            Some(url)
        }
        "trojan" => {
            let password = proxy.get("password").and_then(|v| v.as_str())?;

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
            Some(url)
        }
        "ss" => {
            let method = proxy.get("cipher").and_then(|v| v.as_str())?;
            let password = proxy.get("password").and_then(|v| v.as_str())?;

            let userinfo = format!("{}:{}", method, password);
            let encoded = base64::engine::general_purpose::STANDARD.encode(&userinfo);

            Some(format!(
                "ss://{}@{}:{}#{}",
                encoded,
                server,
                port,
                urlencoding::encode(name)
            ))
        }
        "hysteria2" => {
            let password = proxy.get("password").and_then(|v| v.as_str())?;

            let mut url = format!("hysteria2://{}@{}:{}?", password, server, port);

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
            Some(url)
        }
        "anytls" => {
            let password = proxy.get("password").and_then(|v| v.as_str())?;

            let mut url = format!("anytls://{}@{}:{}?", password, server, port);

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
            Some(url)
        }
        "ssr" => {
            let method = proxy.get("cipher").and_then(|v| v.as_str())?;
            let password = proxy.get("password").and_then(|v| v.as_str())?;
            let protocol = proxy
                .get("protocol")
                .and_then(|v| v.as_str())
                .unwrap_or("origin");
            let obfs = proxy
                .get("obfs")
                .and_then(|v| v.as_str())
                .unwrap_or("plain");

            let password_encoded = base64::engine::general_purpose::STANDARD.encode(password);
            let srchost = format!(
                "{}:{}:{}:{}:{}:{}/?obfsparam=&protoparam=&remarks={}",
                server,
                port,
                protocol,
                method,
                obfs,
                password_encoded,
                base64::engine::general_purpose::STANDARD.encode(name)
            );
            let encoded = base64::engine::general_purpose::STANDARD.encode(&srchost);
            Some(format!("ssr://{}", encoded))
        }
        _ => None,
    }
}

fn source_from_request(req: &ConvertRequest) -> Result<String, String> {
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
        let raw = format!("raw:{}", content);
        return sanitize_source(&raw);
    }

    Err("Either subscription_url or content is required".to_string())
}

async fn parse_source_async(source: &str, format: &TargetFormat) -> Result<String, String> {
    let source = sanitize_source(source)?;

    if let Some(raw) = source.strip_prefix("raw:") {
        if raw.trim().is_empty() {
            return Err("Raw subscription content cannot be empty".to_string());
        }
        return Ok(raw.to_string());
    }

    fetch_subscription(&source, format).await
}

#[derive(Clone)]
struct SubscribeTokenEntry {
    source: String,
    format: TargetFormat,
    include_direct: bool,
    include_dns: bool,
    expires_at: Instant,
}

fn token_store() -> &'static Mutex<HashMap<String, SubscribeTokenEntry>> {
    static STORE: OnceLock<Mutex<HashMap<String, SubscribeTokenEntry>>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn build_query_subscription_path(
    source: &str,
    format: &TargetFormat,
    include_direct: bool,
    include_dns: bool,
) -> String {
    format!(
        "/api/sub/subscribe?source={}&format={}&include_direct={}&include_dns={}",
        urlencoding::encode(source),
        format.as_str(),
        include_direct,
        include_dns
    )
}

fn build_token_subscription_path(
    source: &str,
    format: &TargetFormat,
    include_direct: bool,
    include_dns: bool,
) -> String {
    let id = Uuid::now_v7().to_string();
    let expires_at = Instant::now() + Duration::from_secs(60 * 60);

    if let Ok(mut store) = token_store().lock() {
        store.retain(|_, entry| entry.expires_at > Instant::now());
        store.insert(
            id.clone(),
            SubscribeTokenEntry {
                source: source.to_string(),
                format: format.clone(),
                include_direct,
                include_dns,
                expires_at,
            },
        );
    }

    format!("/api/sub/subscribe/{}", id)
}

async fn subscribe_by_token(Path(id): Path<String>) -> impl IntoResponse {
    let entry = {
        let mut store = match token_store().lock() {
            Ok(store) => store,
            Err(_) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Subscription store is unavailable",
                )
                    .into_response();
            }
        };

        store.retain(|_, entry| entry.expires_at > Instant::now());
        store.get(&id).cloned()
    };

    let entry = match entry {
        Some(entry) => entry,
        None => {
            return (
                StatusCode::NOT_FOUND,
                "Subscription link expired or invalid",
            )
                .into_response();
        }
    };

    let content = match parse_source_async(&entry.source, &entry.format).await {
        Ok(content) => content,
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };

    let proxy_urls = parse_subscription_content(&content);
    if proxy_urls.is_empty() {
        return (StatusCode::BAD_REQUEST, "No valid proxy URLs found").into_response();
    }

    let (result, _, _) = match build_content(
        &proxy_urls,
        &entry.format,
        entry.include_direct,
        entry.include_dns,
    ) {
        Ok(result) => result,
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(entry.format.content_type())
            .unwrap_or(HeaderValue::from_static("text/plain; charset=utf-8")),
    );

    (StatusCode::OK, headers, result).into_response()
}
async fn convert_subscription(Json(req): Json<ConvertRequest>) -> Json<ConvertResponse> {
    let source = match source_from_request(&req) {
        Ok(source) => source,
        Err(e) => {
            return Json(ConvertResponse {
                success: false,
                subscription_path: None,
                preview_content: None,
                content_type: None,
                code_class: None,
                format: None,
                proxies: vec![],
                outbounds_count: 0,
                error: Some(e),
            });
        }
    };

    let _preset = req.preset.as_deref().unwrap_or("default");

    let content = match parse_source_async(&source, &req.format).await {
        Ok(content) => content,
        Err(e) => {
            return Json(ConvertResponse {
                success: false,
                subscription_path: None,
                preview_content: None,
                content_type: None,
                code_class: None,
                format: None,
                proxies: vec![],
                outbounds_count: 0,
                error: Some(e),
            });
        }
    };

    let proxy_urls = parse_subscription_content(&content);

    if proxy_urls.is_empty() {
        return Json(ConvertResponse {
            success: false,
            subscription_path: None,
            preview_content: None,
            content_type: None,
            code_class: None,
            format: None,
            proxies: vec![],
            outbounds_count: 0,
            error: Some("No valid proxy URLs found in subscription".to_string()),
        });
    }

    let (preview_content, proxies, outbounds_count) = match build_content(
        &proxy_urls,
        &req.format,
        req.include_direct,
        req.include_dns,
    ) {
        Ok(result) => result,
        Err(e) => {
            return Json(ConvertResponse {
                success: false,
                subscription_path: None,
                preview_content: None,
                content_type: None,
                code_class: None,
                format: None,
                proxies: vec![],
                outbounds_count: 0,
                error: Some(e),
            });
        }
    };

    let subscription_path = if req
        .subscription_url
        .as_ref()
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false)
    {
        build_query_subscription_path(&source, &req.format, req.include_direct, req.include_dns)
    } else {
        build_token_subscription_path(&source, &req.format, req.include_direct, req.include_dns)
    };

    Json(ConvertResponse {
        success: true,
        subscription_path: Some(subscription_path),
        preview_content: Some(preview_content),
        content_type: Some(req.format.content_type().to_string()),
        code_class: Some(req.format.code_class().to_string()),
        format: Some(req.format.as_str().to_string()),
        proxies,
        outbounds_count,
        error: None,
    })
}

async fn subscribe(Query(req): Query<SubscribeQuery>) -> impl IntoResponse {
    let source = match sanitize_source(&req.source) {
        Ok(source) => source,
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };

    let content = match parse_source_async(&source, &req.format).await {
        Ok(content) => content,
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };

    let proxy_urls = parse_subscription_content(&content);
    if proxy_urls.is_empty() {
        return (StatusCode::BAD_REQUEST, "No valid proxy URLs found").into_response();
    }

    let (result, _, _) = match build_content(
        &proxy_urls,
        &req.format,
        req.include_direct,
        req.include_dns,
    ) {
        Ok(result) => result,
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(req.format.content_type())
            .unwrap_or(HeaderValue::from_static("text/plain; charset=utf-8")),
    );

    (StatusCode::OK, headers, result).into_response()
}

pub fn router() -> Router {
    Router::new()
        .route("/convert", post(convert_subscription))
        .route("/subscribe", get(subscribe))
        .route("/subscribe/{id}", get(subscribe_by_token))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    async fn post_convert(body: serde_json::Value) -> (StatusCode, serde_json::Value) {
        let app = router();
        let req = Request::builder()
            .method("POST")
            .uri("/convert")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        (status, json)
    }

    async fn get_subscribe(uri: &str) -> (StatusCode, String, Option<String>) {
        let app = router();
        let req = Request::builder()
            .method("GET")
            .uri(uri)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let status = resp.status();
        let content_type = resp
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let body = String::from_utf8_lossy(&bytes).to_string();
        (status, body, content_type)
    }

    const SAMPLE_SUB: &str = "vmess://eyJ2IjoiMiIsInBzIjoiVGVzdC1WbWVzcyIsImFkZCI6ImV4YW1wbGUuY29tIiwicG9ydCI6IjQ0MyIsImlkIjoiNzQwNjYwYjktYmQxMi00NWE2LTk2MGYtNmI0N2RkNGNiZTY2IiwiYWlkIjoiMCIsIm5ldCI6IndzIiwidHlwZSI6Im5vbmUiLCJob3N0IjoiZXhhbXBsZS5jb20iLCJwYXRoIjoiLyIsInRscyI6InRscyJ9";

    #[tokio::test]
    async fn test_convert_default_format_is_subscription() {
        let body = serde_json::json!({
            "content": SAMPLE_SUB,
            "include_direct": true,
            "include_dns": false
        });

        let (status, json) = post_convert(body).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["success"], true);
        assert_eq!(json["format"], "subscription");
        assert_eq!(json["content_type"], "text/plain; charset=utf-8");

        let preview = json["preview_content"].as_str().unwrap().trim();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(preview)
            .unwrap();
        let decoded_text = String::from_utf8(decoded).unwrap();
        assert!(decoded_text.contains("vmess://"));
    }

    #[tokio::test]
    async fn test_convert_returns_subscription_path() {
        let body = serde_json::json!({
            "content": SAMPLE_SUB,
            "format": "singbox",
            "include_direct": true,
            "include_dns": true
        });

        let (status, json) = post_convert(body).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["success"], true);
        let path = json["subscription_path"].as_str().unwrap();
        assert!(path.starts_with("/api/sub/subscribe/"));
        assert!(path.len() > "/api/sub/subscribe/".len());
        assert!(
            json["preview_content"]
                .as_str()
                .unwrap()
                .contains("outbounds")
        );
    }

    #[test]
    fn test_build_query_subscription_path() {
        let path = build_query_subscription_path(
            "https://example.com/sub?token=abc",
            &TargetFormat::Clash,
            true,
            false,
        );
        assert!(path.starts_with("/api/sub/subscribe?"));
        assert!(path.contains("source=https%3A%2F%2Fexample.com%2Fsub%3Ftoken%3Dabc"));
        assert!(path.contains("format=clash"));
        assert!(path.contains("include_direct=true"));
        assert!(path.contains("include_dns=false"));
    }

    #[tokio::test]
    async fn test_subscribe_by_token_singbox_content_type() {
        let body = serde_json::json!({
            "content": SAMPLE_SUB,
            "format": "singbox",
            "include_direct": true,
            "include_dns": false
        });

        let (status, json) = post_convert(body).await;
        assert_eq!(status, StatusCode::OK);
        let path = json["subscription_path"].as_str().unwrap();

        let api_uri = path.trim_start_matches("/api/sub");
        let (status, body, content_type) = get_subscribe(api_uri).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            content_type
                .unwrap_or_default()
                .starts_with("application/json")
        );
        assert!(body.contains("outbounds"));
        assert!(!body.contains("\"type\": \"block\""));
        assert!(!body.contains("\"type\": \"dns\""));
    }

    #[tokio::test]
    async fn test_subscribe_by_token_not_found() {
        let (status, body, _) = get_subscribe("/subscribe/not-found-token").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(body.contains("expired") || body.contains("invalid"));
    }

    #[test]
    fn test_generate_singbox_config_uses_mixed_inbound() {
        let (config, _) = generate_singbox_config(&[SAMPLE_SUB.to_string()], true, true);
        let inbounds = config["inbounds"].as_array().unwrap();
        let first = inbounds.first().unwrap();
        assert_eq!(first["type"].as_str().unwrap(), "mixed");
        assert_eq!(first["listen"].as_str().unwrap(), "127.0.0.1");
        assert_eq!(first["listen_port"].as_u64().unwrap(), 10808);
    }

    #[tokio::test]
    async fn test_subscribe_v2ray_content_type_and_plain_lines() {
        let source = format!("raw:{}", SAMPLE_SUB);
        let uri = format!(
            "/subscribe?source={}&format=v2ray&include_direct=true&include_dns=false",
            urlencoding::encode(&source)
        );
        let (status, body, content_type) = get_subscribe(&uri).await;
        assert_eq!(status, StatusCode::OK);
        assert!(content_type.unwrap_or_default().starts_with("text/plain"));
        let text = body.trim();
        assert!(text.starts_with("vmess://"));
        assert!(
            base64::engine::general_purpose::STANDARD
                .decode(text)
                .is_err(),
            "v2ray format should be plain URI lines, not base64 wrapped"
        );
    }
    #[test]
    fn test_parse_vless_reality_preserves_tls_fields() {
        let url = "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=tcp&security=reality&sni=www.google.com&fp=chrome&pbk=abcdef123456&sid=11#r1";
        let outbound = parse_vless(url).unwrap();
        assert_eq!(outbound["type"], "vless");
        assert_eq!(outbound["tls"]["enabled"], true);
        assert_eq!(outbound["tls"]["server_name"], "www.google.com");
        assert_eq!(outbound["tls"]["utls"]["fingerprint"], "chrome");
        assert_eq!(outbound["tls"]["reality"]["enabled"], true);
        assert_eq!(outbound["tls"]["reality"]["public_key"], "abcdef123456");
    }

    #[test]
    fn test_parse_trojan_preserves_sni_fingerprint() {
        let url = "trojan://pass@example.com:443?type=ws&host=cdn.example.com&path=%2Fws&sni=www.google.com&fp=chrome&alpn=h2,http/1.1#t1";
        let outbound = parse_trojan(url).unwrap();
        assert_eq!(outbound["type"], "trojan");
        assert_eq!(outbound["tls"]["server_name"], "www.google.com");
        assert_eq!(outbound["tls"]["utls"]["fingerprint"], "chrome");
        assert_eq!(outbound["tls"]["alpn"][0], "h2");
        assert_eq!(outbound["transport"]["type"], "ws");
    }

    #[test]
    fn test_generate_clash_yaml_preserves_grpc_tls_fields() {
        let vless = "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=grpc&serviceName=svc&sni=www.google.com&security=tls&fp=chrome&alpn=h2,http/1.1#g1";
        let (yaml, _) = generate_clash_yaml(&[vless.to_string()], true, false).unwrap();
        let doc: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
        let proxies = doc["proxies"].as_sequence().unwrap();
        let first = proxies.first().unwrap();
        assert_eq!(first["network"].as_str().unwrap(), "grpc");
        assert_eq!(
            first["grpc-opts"]["grpc-service-name"].as_str().unwrap(),
            "svc"
        );
        assert_eq!(first["client-fingerprint"].as_str().unwrap(), "chrome");
        assert_eq!(first["alpn"][0].as_str().unwrap(), "h2");
        assert_eq!(first["servername"].as_str().unwrap(), "www.google.com");
    }

    #[test]
    fn test_clash_trojan_to_url_preserves_servername_host_and_fingerprint() {
        let yaml = r#"
proxies:
  - name: trojan-test
    type: trojan
    server: example.com
    port: 443
    password: pass
    tls: true
    servername: www.google.com
    client-fingerprint: chrome
    alpn:
      - h2
      - http/1.1
    network: ws
    ws-opts:
      path: /ws
      headers:
        Host: cdn.example.com
"#;

        let urls = parse_clash_yaml(yaml);
        assert_eq!(urls.len(), 1);
        let url = &urls[0];
        assert!(url.starts_with("trojan://pass@example.com:443?"));
        assert!(url.contains("security=tls"));
        assert!(url.contains("sni=www.google.com"));
        assert!(url.contains("fp=chrome"));
        assert!(url.contains("alpn=h2%2Chttp%2F1.1"));
        assert!(url.contains("type=ws"));
        assert!(url.contains("path=%2Fws"));
        assert!(url.contains("host=cdn.example.com"));
    }

    #[test]
    fn test_parse_subscription_content_accepts_anytls_raw_lines() {
        let content = "anytls://pass@example.com:443?sni=www.google.com#any\nvmess://abc";
        let urls = parse_subscription_content(content);
        assert_eq!(urls.len(), 2);
        assert!(urls.iter().any(|u| u.starts_with("anytls://")));
    }

    #[test]
    fn test_parse_subscription_content_accepts_anytls_in_base64_subscription() {
        let raw = "anytls://pass@example.com:443?sni=www.google.com#any\nvmess://abc";
        let encoded = base64::engine::general_purpose::STANDARD.encode(raw);
        let urls = parse_subscription_content(&encoded);
        assert_eq!(urls.len(), 2);
        assert!(urls.iter().any(|u| u.starts_with("anytls://")));
    }

    #[test]
    fn test_parse_anytls_preserves_tls_ws_fields() {
        let url = "anytls://pass@example.com:443?type=ws&path=%2Fws&host=cdn.example.com&sni=www.google.com&fp=chrome&alpn=h2,http/1.1&insecure=1#a1";
        let outbound = parse_anytls(url).unwrap();

        assert_eq!(outbound["type"], "anytls");
        assert_eq!(outbound["password"], "pass");
        assert_eq!(outbound["tls"]["server_name"], "www.google.com");
        assert_eq!(outbound["tls"]["insecure"], true);
        assert_eq!(outbound["tls"]["utls"]["fingerprint"], "chrome");
        assert_eq!(outbound["tls"]["alpn"][0], "h2");
        assert_eq!(outbound["transport"]["type"], "ws");
        assert_eq!(outbound["transport"]["path"], "/ws");
        assert_eq!(outbound["transport"]["headers"]["Host"], "cdn.example.com");
    }

    #[test]
    fn test_clash_hysteria2_to_url_preserves_tls_obfs_bandwidth() {
        let yaml = r#"
proxies:
  - name: hy2-test
    type: hysteria2
    server: hy.example.com
    port: 443
    password: pass
    sni: www.google.com
    skip-cert-verify: true
    alpn:
      - h3
    obfs: salamander
    obfs-password: obfspass
    up: 50
    down: 120
"#;

        let urls = parse_clash_yaml(yaml);
        assert_eq!(urls.len(), 1);
        let url = &urls[0];
        assert!(url.starts_with("hysteria2://pass@hy.example.com:443?"));
        assert!(url.contains("sni=www.google.com"));
        assert!(url.contains("insecure=1"));
        assert!(url.contains("alpn=h3"));
        assert!(url.contains("obfs=salamander"));
        assert!(url.contains("obfs-password=obfspass"));
        assert!(url.contains("up=50"));
        assert!(url.contains("down=120"));
    }

    #[test]
    fn test_clash_anytls_to_url_preserves_ws_tls_fields() {
        let yaml = r#"
proxies:
  - name: anytls-test
    type: anytls
    server: any.example.com
    port: 443
    password: pass
    servername: www.google.com
    client-fingerprint: chrome
    alpn:
      - h2
      - http/1.1
    skip-cert-verify: true
    network: ws
    ws-opts:
      path: /ws
      headers:
        Host: cdn.example.com
"#;

        let urls = parse_clash_yaml(yaml);
        assert_eq!(urls.len(), 1);
        let url = &urls[0];
        assert!(url.starts_with("anytls://pass@any.example.com:443?"));
        assert!(url.contains("sni=www.google.com"));
        assert!(url.contains("fp=chrome"));
        assert!(url.contains("alpn=h2%2Chttp%2F1.1"));
        assert!(url.contains("insecure=1"));
        assert!(url.contains("type=ws"));
        assert!(url.contains("path=%2Fws"));
        assert!(url.contains("host=cdn.example.com"));
    }

    #[tokio::test]
    async fn test_private_ip_url_rejected() {
        let body = serde_json::json!({
            "subscription_url": "http://127.0.0.1/test",
            "format": "singbox",
            "include_direct": true,
            "include_dns": true
        });

        let (status, json) = post_convert(body).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["success"], false);
        assert!(
            json["error"].as_str().unwrap().contains("Private IP")
                || json["error"].as_str().unwrap().contains("localhost")
        );
    }
}
