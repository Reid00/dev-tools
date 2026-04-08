use axum::{Json, Router, routing::post};
use base64::Engine;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;

// Re-export urlencoding for use in the module
use urlencoding;

// ── Request / Response types ───────────────────────────────────────

#[derive(Deserialize)]
pub struct ConvertRequest {
    pub subscription_url: String,
    #[serde(default)]
    pub include_direct: bool,
    #[serde(default)]
    pub include_dns: bool,
}

#[derive(Serialize)]
pub struct ConvertResponse {
    pub success: bool,
    pub config: Option<Value>,
    pub outbounds_count: usize,
    pub error: Option<String>,
}

#[derive(Deserialize)]
pub struct ParseRequest {
    pub content: String,
    #[serde(default)]
    pub include_direct: bool,
    #[serde(default)]
    pub include_dns: bool,
}

#[derive(Serialize)]
pub struct ParseResponse {
    pub success: bool,
    pub config: Option<Value>,
    pub outbounds_count: usize,
    pub proxies: Vec<ProxyInfo>,
    pub error: Option<String>,
}

#[derive(Serialize)]
pub struct ProxyInfo {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub protocol: String,
}

// ── Proxy URL parsing ───────────────────────────────────────────────

/// Parse a vmess:// URL
fn parse_vmess(url: &str) -> Result<Value, String> {
    // vmess://base64_encoded_json
    let base64_part = url.strip_prefix("vmess://")
        .ok_or("Invalid vmess URL prefix")?;

    // Handle URL-safe base64
    let base64_part = base64_part.replace('-', "+").replace('_', "/");

    // Add padding if needed
    let padding = (4 - base64_part.len() % 4) % 4;
    let base64_part = base64_part + &"=".repeat(padding);

    let json_str = base64_decode(&base64_part)?;
    let vmess: HashMap<String, Value> = serde_json::from_str(&json_str)
        .map_err(|e| format!("Failed to parse vmess JSON: {}", e))?;

    // Extract fields
    let add = vmess.get("add").and_then(|v| v.as_str()).unwrap_or("");
    let port = vmess.get("port").and_then(|v| v.as_str())
        .and_then(|s| s.parse::<u16>().ok()).unwrap_or(443);
    let id = vmess.get("id").and_then(|v| v.as_str()).unwrap_or("");
    let net = vmess.get("net").and_then(|v| v.as_str()).unwrap_or("tcp");
    let ps = vmess.get("ps").and_then(|v| v.as_str()).unwrap_or("vmess");
    let tls = vmess.get("tls").and_then(|v| v.as_str()).unwrap_or("");
    let host = vmess.get("host").and_then(|v| v.as_str()).unwrap_or("");
    let path = vmess.get("path").and_then(|v| v.as_str()).unwrap_or("/");
    let aid = vmess.get("aid").and_then(|v| v.as_str())
        .and_then(|s| s.parse::<u32>().ok()).unwrap_or(0);

    // Build sing-box outbound
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

    // Add transport if not tcp
    if net == "ws" {
        let transport = json!({
            "type": "ws",
            "path": path,
            "headers": if host.is_empty() {
                json!({})
            } else {
                json!({"Host": host})
            }
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

    // Add TLS if enabled
    if tls == "tls" {
        outbound["tls"] = json!({
            "enabled": true,
            "server_name": if host.is_empty() { json!(add) } else { json!(host) },
            "insecure": false
        });
    }

    Ok(outbound)
}

/// Parse a vless:// URL
fn parse_vless(url: &str) -> Result<Value, String> {
    // vless://uuid@server:port?params#name
    let url = url.strip_prefix("vless://")
        .ok_or("Invalid vless URL prefix")?;

    // Parse as URL
    let parsed = Url::parse(&format!("vless://{}", url))
        .map_err(|e| format!("Failed to parse vless URL: {}", e))?;

    let uuid = parsed.username();
    let server = parsed.host_str().unwrap_or("");
    let port = parsed.port().unwrap_or(443);

    // Get name from fragment
    let name = parsed.fragment().unwrap_or("vless");

    // Parse query params
    let params: HashMap<String, String> = parsed.query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    let net = params.get("type").unwrap_or(&"tcp".to_string()).clone();
    let tls = params.get("security").unwrap_or(&"".to_string()).clone();
    let host = params.get("host").unwrap_or(&"".to_string()).clone();
    let path = params.get("path").unwrap_or(&"/".to_string()).clone();
    let flow = params.get("flow").unwrap_or(&"".to_string()).clone();

    let mut outbound = json!({
        "type": "vless",
        "tag": name,
        "server": server,
        "server_port": port,
        "uuid": uuid,
        "network": "tcp"
    });

    // Add flow if present (for XTLS)
    if !flow.is_empty() {
        outbound["flow"] = json!(flow);
    }

    // Add transport
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

    // Add TLS
    if tls == "tls" || tls == "reality" {
        if tls == "reality" {
            let pbk = params.get("pbk").unwrap_or(&"".to_string()).clone();
            let sid = params.get("sid").unwrap_or(&"".to_string()).clone();
            outbound["tls"] = json!({
                "enabled": true,
                "server_name": host,
                "reality": {
                    "enabled": true,
                    "public_key": pbk,
                    "short_id": sid
                }
            });
        } else {
            outbound["tls"] = json!({
                "enabled": true,
                "server_name": if host.is_empty() { json!(server) } else { json!(host) }
            });
        }
    }

    Ok(outbound)
}

/// Parse a trojan:// URL
fn parse_trojan(url: &str) -> Result<Value, String> {
    // trojan://password@server:port?params#name
    let url = url.strip_prefix("trojan://")
        .ok_or("Invalid trojan URL prefix")?;

    let parsed = Url::parse(&format!("trojan://{}", url))
        .map_err(|e| format!("Failed to parse trojan URL: {}", e))?;

    let password = parsed.username();
    let server = parsed.host_str().unwrap_or("");
    let port = parsed.port().unwrap_or(443);
    let name = parsed.fragment().unwrap_or("trojan");

    let params: HashMap<String, String> = parsed.query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    let net = params.get("type").unwrap_or(&"tcp".to_string()).clone();
    let host = params.get("host").unwrap_or(&"".to_string()).clone();
    let path = params.get("path").unwrap_or(&"/".to_string()).clone();

    let mut outbound = json!({
        "type": "trojan",
        "tag": name,
        "server": server,
        "server_port": port,
        "password": password,
        "network": "tcp"
    });

    // Add transport
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

    // Trojan always uses TLS
    outbound["tls"] = json!({
        "enabled": true,
        "server_name": if host.is_empty() { json!(server) } else { json!(host) }
    });

    Ok(outbound)
}

/// Parse a ss:// URL (Shadowsocks)
fn parse_ss(url: &str) -> Result<Value, String> {
    // ss://base64(method:password)@server:port#name
    // or ss://base64#name (legacy format)
    let url = url.strip_prefix("ss://")
        .ok_or("Invalid ss URL prefix")?;

    let parsed = Url::parse(&format!("ss://{}", url))
        .map_err(|e| format!("Failed to parse ss URL: {}", e))?;

    let server = parsed.host_str().unwrap_or("");
    let port = parsed.port().unwrap_or(8388);
    let name = parsed.fragment().unwrap_or("ss");

    // Decode userinfo (method:password)
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

/// Parse a ssr:// URL (ShadowsocksR)
fn parse_ssr(url: &str) -> Result<Value, String> {
    // ssr://base64(server:port:protocol:method:obfs:password_base64/?params)
    let base64_part = url.strip_prefix("ssr://")
        .ok_or("Invalid ssr URL prefix")?;

    let decoded = base64_decode(base64_part)?;
    // SSR is legacy, convert to basic shadowsocks
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

/// Base64 decode helper
fn base64_decode(input: &str) -> Result<String, String> {
    // Remove whitespace and newlines from base64 content
    let input: String = input.chars()
        .filter(|c| !c.is_whitespace())
        .collect();

    // Handle URL-safe base64
    let input = input.replace('-', "+").replace('_', "/");

    // Add padding
    let padding = (4 - input.len() % 4) % 4;
    let input = input + &"=".repeat(padding);

    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(&input)
        .map(|bytes| String::from_utf8_lossy(&bytes).to_string())
        .map_err(|e| format!("Base64 decode error: {}", e))
}

// ── Subscription fetching and parsing ─────────────────────────────────

/// Fetch and parse subscription URL
async fn fetch_subscription(url: &str) -> Result<String, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .danger_accept_invalid_certs(false)
        .build()
        .map_err(|e| format!("Failed to create client: {}", e))?;

    let resp = client.get(url)
        .header("User-Agent", "ClashForWindows/0.20.39")
        .header("Accept", "*/*")
        .send()
        .await
        .map_err(|e| format!("Failed to fetch subscription: {}", e))?;

    // Check status
    if !resp.status().is_success() {
        return Err(format!("HTTP error: {}", resp.status()));
    }

    let text = resp.text()
        .await
        .map_err(|e| format!("Failed to read response: {}", e))?;

    // Log for debugging
    tracing::info!("Subscription response length: {} bytes", text.len());
    tracing::info!("First 200 chars: {:?}", &text.chars().take(200).collect::<String>());

    Ok(text)
}

/// Parse subscription content (base64 encoded lines or Clash YAML)
fn parse_subscription_content(content: &str) -> Vec<String> {
    // Clean up content - remove whitespace
    let content = content.trim();

    tracing::info!("Parsing subscription content, length: {} bytes", content.len());

    // Check if it's already proxy URLs (starts with vmess://, etc.)
    if content.starts_with("vmess://") || content.starts_with("vless://") ||
       content.starts_with("trojan://") || content.starts_with("ss://") {
        let urls: Vec<String> = content.lines()
            .map(|line| line.trim())
            .filter(|line| !line.is_empty())
            .filter(|line| {
                line.starts_with("vmess://") ||
                line.starts_with("vless://") ||
                line.starts_with("trojan://") ||
                line.starts_with("ss://") ||
                line.starts_with("ssr://")
            })
            .map(|s| s.to_string())
            .collect();
        tracing::info!("Found {} proxy URLs directly", urls.len());
        return urls;
    }

    // Check if it's a Clash YAML config
    if content.starts_with("port:") || content.starts_with("mixed-port:") ||
       content.contains("proxies:") {
        tracing::info!("Detected Clash YAML format");
        return parse_clash_yaml(content);
    }

    // Try base64 decode
    let decoded = match base64_decode(content) {
        Ok(d) => {
            tracing::info!("Successfully decoded base64, decoded length: {} bytes", d.len());
            d
        },
        Err(e) => {
            tracing::info!("Base64 decode failed: {}, using raw content", e);
            content.to_string()
        },
    };

    // Check if decoded content is Clash YAML
    if decoded.starts_with("port:") || decoded.starts_with("mixed-port:") ||
       decoded.contains("proxies:") {
        tracing::info!("Decoded content is Clash YAML format");
        return parse_clash_yaml(&decoded);
    }

    // Split into lines and filter valid proxy URLs
    let urls: Vec<String> = decoded.lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty())
        .filter(|line| {
            line.starts_with("vmess://") ||
            line.starts_with("vless://") ||
            line.starts_with("trojan://") ||
            line.starts_with("ss://") ||
            line.starts_with("ssr://")
        })
        .map(|s| s.to_string())
        .collect();

    tracing::info!("Found {} proxy URLs", urls.len());
    urls
}

/// Parse Clash YAML configuration and extract proxy URLs
fn parse_clash_yaml(content: &str) -> Vec<String> {
    let mut urls = Vec::new();

    // Parse YAML
    let yaml: serde_yaml::Value = match serde_yaml::from_str(content) {
        Ok(y) => y,
        Err(e) => {
            tracing::error!("Failed to parse YAML: {}", e);
            return urls;
        }
    };

    // Get proxies array
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
            // Convert Clash proxy to URL
            if let Some(url) = clash_proxy_to_url(proxy_obj) {
                urls.push(url);
            }
        }
    }

    urls
}

/// Convert a Clash proxy object to a proxy URL
fn clash_proxy_to_url(proxy: &serde_yaml::Mapping) -> Option<String> {
    let proxy_type = proxy.get("type").and_then(|v| v.as_str())?;

    let name = proxy.get("name").and_then(|v| v.as_str()).unwrap_or("proxy");
    let server = proxy.get("server").and_then(|v| v.as_str())?;
    let port = proxy.get("port").and_then(|v| v.as_u64())?;

    match proxy_type {
        "vmess" => {
            let uuid = proxy.get("uuid").and_then(|v| v.as_str())?;
            let alter_id = proxy.get("alterId").and_then(|v| v.as_u64()).unwrap_or(0);
            let network = proxy.get("network").and_then(|v| v.as_str()).unwrap_or("tcp");

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

            // Handle WebSocket
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

            // Handle TLS
            if proxy.get("tls").and_then(|v| v.as_bool()).unwrap_or(false) {
                vmess_obj["tls"] = json!("tls");
                if let Some(sni) = proxy.get("servername").and_then(|v| v.as_str()) {
                    vmess_obj["host"] = json!(sni);
                }
            }

            let vmess_json = serde_json::to_string(&vmess_obj).ok()?;
            let encoded = base64::engine::general_purpose::STANDARD.encode(&vmess_json);
            Some(format!("vmess://{}", encoded))
        },
        "vless" => {
            let uuid = proxy.get("uuid").and_then(|v| v.as_str())?;
            let flow = proxy.get("flow").and_then(|v| v.as_str()).unwrap_or("");

            let mut url = format!("vless://{}@{}:{}?type=tcp", uuid, server, port);

            if !flow.is_empty() {
                url.push_str(&format!("&flow={}", flow));
            }

            // Handle TLS
            if proxy.get("tls").and_then(|v| v.as_bool()).unwrap_or(false) {
                url.push_str("&security=tls");
                if let Some(sni) = proxy.get("servername").and_then(|v| v.as_str()) {
                    url.push_str(&format!("&sni={}", sni));
                }
            }

            // Handle WebSocket
            let network = proxy.get("network").and_then(|v| v.as_str()).unwrap_or("tcp");
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
        },
        "trojan" => {
            let password = proxy.get("password").and_then(|v| v.as_str())?;

            let mut url = format!("trojan://{}@{}:{}", password, server, port);

            // Handle TLS
            url.push_str("?security=tls");
            if let Some(sni) = proxy.get("sni").and_then(|v| v.as_str()) {
                url.push_str(&format!("&sni={}", sni));
            }

            // Handle network type
            let network = proxy.get("network").and_then(|v| v.as_str()).unwrap_or("tcp");
            if network == "ws" {
                url.push_str("&type=ws");
                if let Some(ws_opts) = proxy.get("ws-opts").and_then(|v| v.as_mapping()) {
                    if let Some(path) = ws_opts.get("path").and_then(|v| v.as_str()) {
                        url.push_str(&format!("&path={}", urlencoding::encode(path)));
                    }
                }
            }

            url.push_str(&format!("#{}", urlencoding::encode(name)));
            Some(url)
        },
        "ss" => {
            let method = proxy.get("cipher").and_then(|v| v.as_str())?;
            let password = proxy.get("password").and_then(|v| v.as_str())?;

            let userinfo = format!("{}:{}", method, password);
            let encoded = base64::engine::general_purpose::STANDARD.encode(&userinfo);

            Some(format!("ss://{}@{}:{}#{}", encoded, server, port, urlencoding::encode(name)))
        },
        "ssr" => {
            let method = proxy.get("cipher").and_then(|v| v.as_str())?;
            let password = proxy.get("password").and_then(|v| v.as_str())?;
            let protocol = proxy.get("protocol").and_then(|v| v.as_str()).unwrap_or("origin");
            let obfs = proxy.get("obfs").and_then(|v| v.as_str()).unwrap_or("plain");

            let password_encoded = base64::engine::general_purpose::STANDARD.encode(password);
            let srchost = format!("{}:{}:{}:{}:{}:{}/?obfsparam=&protoparam=&remarks={}",
                server, port, protocol, method, obfs, password_encoded,
                base64::engine::general_purpose::STANDARD.encode(name));
            let encoded = base64::engine::general_purpose::STANDARD.encode(&srchost);
            Some(format!("ssr://{}", encoded))
        },
        _ => None
    }
}

/// Parse all proxy URLs and generate sing-box config
fn generate_singbox_config(proxy_urls: &[String], include_direct: bool, include_dns: bool) -> (Value, Vec<ProxyInfo>) {
    let mut outbounds: Vec<Value> = vec![];
    let mut proxies: Vec<ProxyInfo> = vec![];

    // Parse each proxy URL
    for url in proxy_urls {
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
        } else {
            continue;
        };

        if let Ok(outbound) = result {
            // Extract proxy info
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

    // Build selector outbound
    let proxy_tags: Vec<String> = outbounds.iter()
        .filter_map(|o| o["tag"].as_str().map(|s| s.to_string()))
        .collect();

    // Create selector
    let selector = json!({
        "type": "selector",
        "tag": "proxy",
        "outbounds": proxy_tags.clone()
    });

    // Add URL test group
    let urltest = json!({
        "type": "urltest",
        "tag": "auto",
        "outbounds": proxy_tags,
        "url": "https://www.gstatic.com/generate_204",
        "interval": "3m",
        "tolerance": 50
    });

    // Build complete config
    let mut config = json!({
        "log": {
            "level": "info",
            "timestamp": true
        },
        "inbounds": [
            {
                "type": "tun",
                "tag": "tun-in",
                "inet4_address": "172.19.0.1/30",
                "auto_route": true,
                "strict_route": true,
                "stack": "system"
            }
        ],
        "outbounds": vec![selector, urltest]
    });

    // Add all proxy outbounds
    let mut all_outbounds = config["outbounds"].as_array_mut().unwrap().clone();
    all_outbounds.extend(outbounds);

    // Add direct and dns if requested
    if include_direct {
        all_outbounds.push(json!({
            "type": "direct",
            "tag": "direct"
        }));
        all_outbounds.push(json!({
            "type": "block",
            "tag": "block"
        }));
    }

    if include_dns {
        all_outbounds.push(json!({
            "type": "dns",
            "tag": "dns-out"
        }));
    }

    config["outbounds"] = json!(all_outbounds);

    // Add DNS and route
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

    let mut route_rules = vec![
        json!({"action": "sniff"}),
        json!({"protocol": "dns", "action": "hijack-dns"})
    ];

    if include_direct {
        route_rules.push(json!({"ip_is_private": true, "outbound": "direct"}));
    }

    config["route"] = json!({
        "rules": route_rules,
        "default_domain_resolver": "local",
        "auto_detect_interface": true,
        "final": "proxy"
    });

    (config, proxies)
}

// ── Handlers ───────────────────────────────────────────────────────

async fn convert_subscription(Json(req): Json<ConvertRequest>) -> Json<ConvertResponse> {
    // Fetch subscription
    let content = match fetch_subscription(&req.subscription_url).await {
        Ok(c) => c,
        Err(e) => return Json(ConvertResponse {
            success: false,
            config: None,
            outbounds_count: 0,
            error: Some(e),
        }),
    };

    // Parse content
    let proxy_urls = parse_subscription_content(&content);

    if proxy_urls.is_empty() {
        return Json(ConvertResponse {
            success: false,
            config: None,
            outbounds_count: 0,
            error: Some("No valid proxy URLs found in subscription".to_string()),
        });
    }

    // Generate sing-box config
    let (config, _) = generate_singbox_config(&proxy_urls, req.include_direct, req.include_dns);
    let outbounds_count = config["outbounds"].as_array().map(|a| a.len()).unwrap_or(0);

    Json(ConvertResponse {
        success: true,
        config: Some(config),
        outbounds_count,
        error: None,
    })
}

async fn parse_content(Json(req): Json<ParseRequest>) -> Json<ParseResponse> {
    let proxy_urls = parse_subscription_content(&req.content);

    if proxy_urls.is_empty() {
        return Json(ParseResponse {
            success: false,
            config: None,
            outbounds_count: 0,
            proxies: vec![],
            error: Some("No valid proxy URLs found".to_string()),
        });
    }

    let (config, proxies) = generate_singbox_config(&proxy_urls, req.include_direct, req.include_dns);
    let outbounds_count = config["outbounds"].as_array().map(|a| a.len()).unwrap_or(0);

    Json(ParseResponse {
        success: true,
        config: Some(config),
        outbounds_count,
        proxies,
        error: None,
    })
}

// ── Router ─────────────────────────────────────────────────────────

pub fn router() -> Router {
    Router::new()
        .route("/convert", post(convert_subscription))
        .route("/parse", post(parse_content))
}
