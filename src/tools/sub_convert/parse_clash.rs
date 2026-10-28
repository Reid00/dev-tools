use super::types::{ProxyNode, ProxyProtocol, TransportType};
use serde_yaml::Mapping;

#[cfg(test)]
pub fn parse_clash_yaml(content: &str) -> Result<Vec<ProxyNode>, String> {
    parse_clash_entries(content)?
        .into_iter()
        .map(|entry| entry.result)
        .collect()
}

pub(crate) fn parse_clash_entries(content: &str) -> Result<Vec<super::parser::ParsedNode>, String> {
    let yaml: serde_yaml::Value = serde_yaml::from_str(content).map_err(|error| {
        let location = error
            .location()
            .map(|location| format!("（第 {} 行，第 {} 列）", location.line(), location.column()))
            .unwrap_or_default();
        format!("Failed to parse Clash YAML：格式错误{location}")
    })?;
    let proxies = yaml
        .get("proxies")
        .and_then(serde_yaml::Value::as_sequence)
        .ok_or_else(|| {
            "Clash 订阅缺少 proxies 数组；不支持仅含 proxy-providers 的配置，请提供完整节点订阅"
                .to_string()
        })?;
    if proxies.is_empty() {
        return Err("Clash proxies 数组为空，没有可转换的节点".to_string());
    }
    Ok(proxies
        .iter()
        .enumerate()
        .map(|(index, value)| {
            let name = value
                .get("name")
                .and_then(serde_yaml::Value::as_str)
                .unwrap_or("未命名")
                .to_string();
            let context = format!("Clash 第 {} 个节点「{name}」", index + 1);
            let result = value
                .as_mapping()
                .ok_or_else(|| "必须是对象".to_string())
                .and_then(clash_proxy_to_node)
                .map_err(|error| format!("{context}：{error}"));
            super::parser::ParsedNode {
                index: index + 1,
                name,
                result,
            }
        })
        .collect())
}

fn clash_proxy_to_node(proxy: &Mapping) -> Result<ProxyNode, String> {
    let mut normalized = proxy.clone();
    for (legacy, current) in [("ws-path", "path"), ("ws-headers", "headers")] {
        if let Some(value) = normalized.remove(legacy) {
            let options = normalized
                .entry("ws-opts".into())
                .or_insert_with(|| serde_yaml::Value::Mapping(Mapping::new()))
                .as_mapping_mut()
                .ok_or("ws-opts 必须为对象")?;
            if options
                .get(current)
                .is_some_and(|existing| existing != &value)
            {
                return Err(format!(
                    "{legacy} 与 ws-opts.{current} 冲突，请保留一种写法"
                ));
            }
            options.insert(current.into(), value);
        }
    }
    let proxy = &normalized;
    let proxy_type = get_required_str(proxy, "type", "缺少字符串字段 type")?;
    if !matches!(
        proxy_type,
        "vmess" | "vless" | "trojan" | "ss" | "ssr" | "hysteria2" | "hy2" | "anytls"
    ) {
        return Err("不支持此 type，无法转换为 sing-box".to_string());
    }
    let name = get_str(proxy, "name").unwrap_or("proxy");
    let server = get_required_str(proxy, "server", "缺少字符串字段 server")?;
    let port = get_u16(proxy, "port")
        .filter(|port| *port > 0)
        .ok_or_else(|| "port 必须在 1–65535 之间".to_string())?;
    let credential = if matches!(proxy_type, "vmess" | "vless") {
        "uuid"
    } else {
        "password"
    };
    if get_str(proxy, credential).is_none_or(str::is_empty) {
        return Err(format!("缺少字符串字段 {credential}"));
    }
    validate_clash_options(proxy, proxy_type)?;
    let node = match proxy_type {
        "vmess" => parse_clash_vmess(proxy, name, server, port),
        "vless" => parse_clash_vless(proxy, name, server, port),
        "trojan" => parse_clash_trojan(proxy, name, server, port),
        "ss" => Some(parse_clash_ss(proxy, name)?),
        "ssr" => Some(parse_clash_ssr(proxy, name)?),
        "hysteria2" | "hy2" => parse_clash_hysteria2(proxy, name, server, port),
        "anytls" => parse_clash_anytls(proxy, name, server, port),
        _ => unreachable!(),
    }
    .ok_or_else(|| "节点缺少必要字段".to_string())?;
    super::parser::validate_required_fields(&node)?;
    Ok(node)
}

fn validate_clash_options(proxy: &Mapping, proxy_type: &str) -> Result<(), String> {
    if get_str(proxy, "network") == Some("http") {
        return Err("Clash network: http 使用 HTTP/1.1 TCP 伪装，与 sing-box HTTP/2 transport 不兼容，无法无损转换".to_string());
    }
    let common = ["name", "type", "server", "port", "udp", "tfo"];
    let protocol_fields: &[&str] = match proxy_type {
        "vmess" => &[
            "uuid",
            "alterId",
            "cipher",
            "tls",
            "skip-cert-verify",
            "servername",
            "sni",
            "client-fingerprint",
            "alpn",
            "network",
            "ws-opts",
            "grpc-opts",
            "h2-opts",
        ],
        "vless" => &[
            "uuid",
            "flow",
            "encryption",
            "tls",
            "skip-cert-verify",
            "servername",
            "sni",
            "client-fingerprint",
            "alpn",
            "network",
            "ws-opts",
            "grpc-opts",
            "h2-opts",
            "reality-opts",
        ],
        "trojan" => &[
            "password",
            "tls",
            "skip-cert-verify",
            "servername",
            "sni",
            "client-fingerprint",
            "alpn",
            "network",
            "ws-opts",
            "grpc-opts",
            "h2-opts",
            "reality-opts",
        ],
        "ss" => &["cipher", "password", "plugin", "plugin-opts"],
        "ssr" => &[
            "cipher",
            "password",
            "protocol",
            "protocol-param",
            "protocol_param",
            "obfs",
            "obfs-param",
            "obfs_param",
        ],
        "hysteria2" | "hy2" => &[
            "password",
            "tls",
            "skip-cert-verify",
            "servername",
            "sni",
            "alpn",
            "obfs",
            "obfs-password",
            "up",
            "down",
        ],
        "anytls" => &[
            "password",
            "tls",
            "skip-cert-verify",
            "servername",
            "sni",
            "client-fingerprint",
            "alpn",
            "network",
            "ws-opts",
            "grpc-opts",
            "h2-opts",
        ],
        _ => unreachable!(),
    };
    for key in proxy.keys() {
        let key = key
            .as_str()
            .ok_or_else(|| "节点字段名必须为字符串".to_string())?;
        if !common.contains(&key) && !protocol_fields.contains(&key) {
            return Err(format!("不支持参数 {key}，无法无损转换"));
        }
    }
    if let Some(network) = proxy.get("network") {
        let network = network
            .as_str()
            .ok_or_else(|| "network 必须为字符串".to_string())?;
        super::parser::parse_transport(network)?;
        if matches!(proxy_type, "ss" | "ssr" | "hysteria2" | "hy2")
            && !matches!(network, "" | "tcp")
        {
            return Err("此协议不支持额外 network，无法无损转换".to_string());
        }
    }
    if matches!(proxy_type, "trojan" | "hysteria2" | "hy2" | "anytls")
        && proxy.get("tls") == Some(&serde_yaml::Value::Bool(false))
    {
        return Err("此协议必须启用 TLS，不能转换 tls: false 节点".to_string());
    }
    if proxy.contains_key("reality-opts")
        && matches!(proxy_type, "vless" | "trojan")
        && proxy_type == "vless"
        && !get_bool(proxy, "tls")
    {
        return Err("Reality 节点必须设置 tls: true".to_string());
    }
    if matches!(proxy_type, "hysteria2" | "hy2") && proxy.contains_key("client-fingerprint") {
        return Err("Hysteria2 不支持 client-fingerprint，无法无损转换".to_string());
    }
    let network = get_str(proxy, "network").unwrap_or("tcp");
    if network == "h2" && !get_bool(proxy, "tls") && !matches!(proxy_type, "trojan" | "anytls") {
        return Err("Clash h2 仅支持启用 TLS 的节点，明文 HTTP/2 无法无损转换".to_string());
    }
    for (option, required_networks) in [
        ("ws-opts", &["ws"][..]),
        ("grpc-opts", &["grpc"][..]),
        ("h2-opts", &["h2"][..]),
    ] {
        if proxy.contains_key(option) && !required_networks.contains(&network) {
            return Err(format!("{option} 与 network 不匹配，无法无损转换"));
        }
    }
    for key in [
        "smux",
        "packet-encoding",
        "dialer-proxy",
        "ports",
        "hop-interval",
        "certificate",
        "private-key",
        "reality-opts",
        "fingerprint",
    ] {
        if key == "reality-opts" && matches!(proxy_type, "vless" | "trojan") {
            continue;
        }
        if proxy.get(key).is_some_and(|value| {
            !value.is_null()
                && value != &serde_yaml::Value::Bool(false)
                && value.as_str() != Some("")
        }) {
            return Err(format!("不支持参数 {key}，无法无损转换"));
        }
    }
    if proxy
        .get("encryption")
        .is_some_and(|value| value.as_str() != Some("none"))
    {
        return Err("不支持 encryption，仅支持 none".to_string());
    }
    for key in ["tls", "skip-cert-verify", "udp", "tfo"] {
        if proxy.get(key).is_some_and(|value| !value.is_bool()) {
            return Err(format!("{key} 必须为布尔值"));
        }
    }
    for key in [
        "servername",
        "sni",
        "client-fingerprint",
        "flow",
        "obfs",
        "obfs-password",
        "plugin",
    ] {
        if proxy.get(key).is_some_and(|value| !value.is_string()) {
            return Err(format!("{key} 必须为字符串"));
        }
    }
    if let Some(alpn) = proxy.get("alpn")
        && !alpn.is_string()
        && !alpn
            .as_sequence()
            .is_some_and(|items| items.iter().all(serde_yaml::Value::is_string))
    {
        return Err("alpn 必须为字符串或字符串数组".to_string());
    }
    if proxy.contains_key("alterId") && get_u32(proxy, "alterId").is_none() {
        return Err("alterId 必须为非负整数".to_string());
    }
    for key in ["up", "down"] {
        if proxy.contains_key(key) && get_u64(proxy, key).is_none() {
            return Err(format!("{key} 必须为整数 Mbps"));
        }
    }
    for key in ["ws-opts", "h2-opts", "grpc-opts", "reality-opts"] {
        if let Some(opts) = proxy.get(key) {
            let opts = opts
                .as_mapping()
                .ok_or_else(|| format!("{key} 必须为对象"))?;
            let allowed: &[&str] = match key {
                "ws-opts" => &["path", "headers"],
                "h2-opts" => &["path", "host"],
                "grpc-opts" => &["grpc-service-name"],
                "reality-opts" => &["public-key", "short-id"],
                _ => unreachable!(),
            };
            if opts
                .keys()
                .any(|key| !key.as_str().is_some_and(|key| allowed.contains(&key)))
            {
                return Err(format!("{key} 包含无法无损转换的选项"));
            }
            if let Some(path) = opts.get("path")
                && !path.is_string()
            {
                return Err(format!("{key}.path 必须为单一路径字符串"));
            }
            if opts
                .get("path")
                .and_then(serde_yaml::Value::as_str)
                .is_some_and(|path| path.contains("?ed=") || path.contains("&ed="))
            {
                return Err(format!(
                    "暂不支持通过 {key}.path 声明 WebSocket early data，无法无损转换"
                ));
            }
            if let Some(headers) = opts.get("headers") {
                let headers = headers
                    .as_mapping()
                    .ok_or_else(|| format!("{key}.headers 必须为对象"))?;
                if headers.keys().any(|key| key.as_str() != Some("Host")) {
                    return Err(format!("{key}.headers 仅支持 Host，其他请求头无法无损转换"));
                }
                if let Some(host) = headers.get("Host")
                    && !host.is_string()
                {
                    return Err(format!("{key}.headers.Host 必须为单一主机字符串"));
                }
            }
            if key == "h2-opts"
                && let Some(host) = opts.get("host")
                && !(host.is_string()
                    || host
                        .as_sequence()
                        .is_some_and(|hosts| hosts.len() == 1 && hosts[0].is_string()))
            {
                return Err("h2-opts.host 仅支持单个主机名，无法保留多主机随机选择".to_string());
            }
            if key == "reality-opts" {
                if opts
                    .get("public-key")
                    .and_then(serde_yaml::Value::as_str)
                    .is_none_or(str::is_empty)
                {
                    return Err("reality-opts 缺少 public-key 字符串".to_string());
                }
                if opts.get("short-id").is_some_and(|value| !value.is_string()) {
                    return Err(
                        "reality-opts.short-id 必须为带引号的字符串，避免丢失前导零".to_string()
                    );
                }
            }
            for key in ["grpc-service-name", "public-key"] {
                if opts.get(key).is_some_and(|value| !value.is_string()) {
                    return Err(format!("{key} 必须为字符串"));
                }
            }
        }
    }
    Ok(())
}

fn get_str<'a>(proxy: &'a Mapping, key: &str) -> Option<&'a str> {
    proxy.get(key).and_then(|value| value.as_str())
}

fn get_u16(proxy: &Mapping, key: &str) -> Option<u16> {
    match proxy.get(key) {
        Some(value) => value
            .as_u64()
            .and_then(|value| u16::try_from(value).ok())
            .or_else(|| value.as_str().and_then(|value| value.parse::<u16>().ok())),
        None => None,
    }
}

fn get_u32(proxy: &Mapping, key: &str) -> Option<u32> {
    match proxy.get(key) {
        Some(value) => value
            .as_u64()
            .and_then(|value| u32::try_from(value).ok())
            .or_else(|| value.as_str().and_then(|value| value.parse::<u32>().ok())),
        None => None,
    }
}

fn get_u64(proxy: &Mapping, key: &str) -> Option<u64> {
    match proxy.get(key) {
        Some(value) => value
            .as_u64()
            .or_else(|| value.as_i64().and_then(|value| u64::try_from(value).ok()))
            .or_else(|| value.as_str().and_then(|value| value.parse::<u64>().ok())),
        None => None,
    }
}

fn get_required_str<'a>(proxy: &'a Mapping, key: &str, error: &str) -> Result<&'a str, String> {
    get_str(proxy, key).ok_or_else(|| error.to_string())
}

fn get_required_u16(proxy: &Mapping, key: &str, error: &str) -> Result<u16, String> {
    get_u16(proxy, key).ok_or_else(|| error.to_string())
}

fn get_bool(proxy: &Mapping, key: &str) -> bool {
    proxy
        .get(key)
        .and_then(|value| value.as_bool())
        .unwrap_or(false)
}

fn get_transport(proxy: &Mapping) -> TransportType {
    match get_str(proxy, "network").unwrap_or("tcp") {
        "ws" => TransportType::Ws,
        "grpc" => TransportType::Grpc,
        "http" | "h2" => TransportType::Http,
        _ => TransportType::Tcp,
    }
}

fn get_explicit_sni(proxy: &Mapping) -> String {
    get_str(proxy, "servername")
        .or_else(|| get_str(proxy, "sni"))
        .unwrap_or("")
        .to_string()
}

fn get_alpn(proxy: &Mapping) -> Vec<String> {
    if let Some(sequence) = proxy.get("alpn").and_then(|value| value.as_sequence()) {
        return sequence
            .iter()
            .filter_map(|value| value.as_str())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
            .collect();
    }

    if let Some(value) = get_str(proxy, "alpn") {
        return value
            .split(',')
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(ToString::to_string)
            .collect();
    }

    Vec::new()
}

fn get_ws_opts(proxy: &Mapping) -> (String, String) {
    let ws_opts = proxy.get("ws-opts").and_then(|value| value.as_mapping());
    let path = ws_opts
        .and_then(|mapping| mapping.get("path"))
        .and_then(|value| value.as_str())
        .unwrap_or("")
        .to_string();
    let host = ws_opts
        .and_then(|mapping| mapping.get("headers"))
        .and_then(|value| value.as_mapping())
        .and_then(|mapping| mapping.get("Host"))
        .and_then(|value| value.as_str())
        .unwrap_or("")
        .to_string();
    (path, host)
}

fn get_grpc_service(proxy: &Mapping) -> String {
    proxy
        .get("grpc-opts")
        .and_then(|value| value.as_mapping())
        .and_then(|mapping| mapping.get("grpc-service-name"))
        .and_then(|value| value.as_str())
        .unwrap_or("")
        .to_string()
}

fn get_reality_opts(proxy: &Mapping) -> (bool, String, String) {
    let Some(reality_opts) = proxy
        .get("reality-opts")
        .and_then(|value| value.as_mapping())
    else {
        return (false, String::new(), String::new());
    };

    let public_key = reality_opts
        .get("public-key")
        .and_then(|value| value.as_str())
        .unwrap_or("")
        .to_string();
    let short_id = reality_opts
        .get("short-id")
        .map(stringify_yaml_scalar)
        .unwrap_or_default();

    (true, public_key, short_id)
}

fn stringify_yaml_scalar(value: &serde_yaml::Value) -> String {
    if let Some(value) = value.as_str() {
        return value.to_string();
    }
    if let Some(value) = value.as_u64() {
        return value.to_string();
    }
    if let Some(value) = value.as_i64() {
        return value.to_string();
    }
    if let Some(value) = value.as_bool() {
        return value.to_string();
    }
    String::new()
}

fn apply_transport_fields(node: &mut ProxyNode, proxy: &Mapping) {
    node.transport = get_transport(proxy);

    match node.transport {
        TransportType::Ws => {
            let (path, host) = get_ws_opts(proxy);
            node.transport_path = path;
            node.transport_host = host;
            node.transport_service.clear();
        }
        TransportType::Grpc => {
            node.transport_service = get_grpc_service(proxy);
            node.transport_path.clear();
            node.transport_host.clear();
        }
        TransportType::Http => {
            let options = proxy.get("h2-opts").and_then(serde_yaml::Value::as_mapping);
            let first_string = |value: &serde_yaml::Value| {
                value
                    .as_str()
                    .or_else(|| {
                        value
                            .as_sequence()
                            .and_then(|items| items.first())
                            .and_then(serde_yaml::Value::as_str)
                    })
                    .unwrap_or("")
                    .to_string()
            };
            node.transport_path = options
                .and_then(|options| options.get("path"))
                .map(first_string)
                .unwrap_or_default();
            node.transport_host = options
                .and_then(|options| options.get("host"))
                .map(first_string)
                .filter(|host| !host.is_empty())
                .unwrap_or_else(|| "www.example.com".to_string());
            node.transport_service.clear();
        }
        TransportType::Tcp => {
            node.transport_path.clear();
            node.transport_host.clear();
            node.transport_service.clear();
        }
    }
}

fn parse_clash_vmess(proxy: &Mapping, name: &str, server: &str, port: u16) -> Option<ProxyNode> {
    let uuid = get_str(proxy, "uuid")?;
    let mut node = ProxyNode::default_with(ProxyProtocol::Vmess, name, server, port);
    node.uuid = uuid.to_string();
    node.alter_id = get_u32(proxy, "alterId").unwrap_or(0);
    node.method = get_str(proxy, "cipher").unwrap_or("auto").to_string();
    node.tls_enabled = get_bool(proxy, "tls");
    node.tls_insecure = get_bool(proxy, "skip-cert-verify");
    node.tls_fingerprint = get_str(proxy, "client-fingerprint")
        .unwrap_or("")
        .to_string();
    node.tls_alpn = get_alpn(proxy);

    apply_transport_fields(&mut node, proxy);

    if node.tls_enabled {
        let explicit_sni = get_explicit_sni(proxy);
        node.tls_sni = if !explicit_sni.is_empty() {
            explicit_sni
        } else if node.transport == TransportType::Ws && !node.transport_host.is_empty() {
            node.transport_host.clone()
        } else {
            server.to_string()
        };
    }

    Some(node)
}

fn parse_clash_vless(proxy: &Mapping, name: &str, server: &str, port: u16) -> Option<ProxyNode> {
    let uuid = get_str(proxy, "uuid")?;
    let mut node = ProxyNode::default_with(ProxyProtocol::Vless, name, server, port);
    node.uuid = uuid.to_string();
    node.flow = get_str(proxy, "flow").unwrap_or("").to_string();
    node.tls_enabled = get_bool(proxy, "tls");
    node.tls_insecure = get_bool(proxy, "skip-cert-verify");
    node.tls_fingerprint = get_str(proxy, "client-fingerprint")
        .unwrap_or("")
        .to_string();
    node.tls_alpn = get_alpn(proxy);

    apply_transport_fields(&mut node, proxy);

    if node.tls_enabled {
        let explicit_sni = get_explicit_sni(proxy);
        node.tls_sni = if !explicit_sni.is_empty() {
            explicit_sni
        } else if node.transport == TransportType::Ws && !node.transport_host.is_empty() {
            node.transport_host.clone()
        } else {
            server.to_string()
        };
    }

    let (reality_enabled, reality_public_key, reality_short_id) = get_reality_opts(proxy);
    node.reality_enabled = reality_enabled;
    node.reality_public_key = reality_public_key;
    node.reality_short_id = reality_short_id;

    Some(node)
}

fn parse_clash_trojan(proxy: &Mapping, name: &str, server: &str, port: u16) -> Option<ProxyNode> {
    let password = get_str(proxy, "password")?;
    let mut node = ProxyNode::default_with(ProxyProtocol::Trojan, name, server, port);
    node.password = password.to_string();
    node.tls_enabled = true;
    node.tls_insecure = get_bool(proxy, "skip-cert-verify");
    node.tls_fingerprint = get_str(proxy, "client-fingerprint")
        .unwrap_or("")
        .to_string();
    node.tls_alpn = get_alpn(proxy);

    apply_transport_fields(&mut node, proxy);

    let explicit_sni = get_str(proxy, "sni")
        .or_else(|| get_str(proxy, "servername"))
        .unwrap_or("")
        .to_string();
    node.tls_sni = if !explicit_sni.is_empty() {
        explicit_sni
    } else if node.transport == TransportType::Ws && !node.transport_host.is_empty() {
        node.transport_host.clone()
    } else {
        server.to_string()
    };

    let (reality_enabled, reality_public_key, reality_short_id) = get_reality_opts(proxy);
    node.reality_enabled = reality_enabled;
    node.reality_public_key = reality_public_key;
    node.reality_short_id = reality_short_id;

    Some(node)
}

fn parse_clash_ss(proxy: &Mapping, name: &str) -> Result<ProxyNode, String> {
    let server = get_required_str(proxy, "server", "Clash SS proxy server is required")?;
    let port = get_required_u16(proxy, "port", "Clash SS proxy port is required")?;
    let method = get_required_str(proxy, "cipher", "Clash SS proxy cipher is required")?;
    let password = get_required_str(proxy, "password", "Clash SS proxy password is required")?;
    let mut node = ProxyNode::default_with(ProxyProtocol::Shadowsocks, name, server, port);
    node.method = method.to_string();
    node.password = password.to_string();
    let plugin = get_str(proxy, "plugin").unwrap_or("");
    node.ss_plugin = if plugin == "obfs" {
        "obfs-local"
    } else {
        plugin
    }
    .to_string();
    node.ss_plugin_opts = match proxy.get("plugin-opts") {
        None => String::new(),
        Some(serde_yaml::Value::String(options)) => options.clone(),
        Some(serde_yaml::Value::Mapping(options)) => {
            if !matches!(plugin, "obfs" | "obfs-local" | "v2ray-plugin") {
                return Err(
                    "无法转换此 plugin 的 plugin-opts 对象，请使用 SIP003 参数字符串".to_string(),
                );
            }
            let mut rendered = Vec::new();
            for (key, value) in options {
                let key = key
                    .as_str()
                    .ok_or_else(|| "plugin-opts 的键必须为字符串".to_string())?;
                let key = if matches!(plugin, "obfs" | "obfs-local") {
                    match key {
                        "mode" | "obfs" => "obfs",
                        "host" | "obfs-host" => "obfs-host",
                        _ => return Err("obfs plugin-opts 仅支持 mode 和 host".to_string()),
                    }
                } else {
                    match key {
                        "mode" | "host" | "path" | "tls" | "mux" => key,
                        _ => return Err("v2ray-plugin 包含无法无损转换的 plugin-opts".to_string()),
                    }
                };
                match value {
                    serde_yaml::Value::Bool(true) if matches!(key, "tls" | "mux") => {
                        rendered.push(key.to_string())
                    }
                    serde_yaml::Value::Bool(false) if key == "tls" => {}
                    serde_yaml::Value::Bool(false) if key == "mux" => {
                        rendered.push("mux=0".to_string())
                    }
                    serde_yaml::Value::String(value)
                        if !value.contains(';') && !value.contains('\n') =>
                    {
                        rendered.push(format!("{key}={value}"))
                    }
                    _ => return Err("plugin-opts 参数类型无效或包含分隔符".to_string()),
                }
            }
            rendered.join(";")
        }
        _ => return Err("plugin-opts 必须为对象或 SIP003 参数字符串".to_string()),
    };
    if node.ss_plugin.is_empty() && !node.ss_plugin_opts.is_empty() {
        return Err("存在 plugin-opts 但缺少 plugin".to_string());
    }
    Ok(node)
}

fn parse_clash_hysteria2(
    proxy: &Mapping,
    name: &str,
    server: &str,
    port: u16,
) -> Option<ProxyNode> {
    let password = get_str(proxy, "password")?;
    let mut node = ProxyNode::default_with(ProxyProtocol::Hysteria2, name, server, port);
    node.password = password.to_string();
    node.tls_enabled = true;
    node.tls_insecure = get_bool(proxy, "skip-cert-verify");
    node.tls_alpn = get_alpn(proxy);
    node.tls_sni = get_str(proxy, "sni")
        .or_else(|| get_str(proxy, "servername"))
        .unwrap_or(server)
        .to_string();
    node.hy2_obfs_type = get_str(proxy, "obfs").unwrap_or("").to_string();
    node.hy2_obfs_password = get_str(proxy, "obfs-password").unwrap_or("").to_string();
    node.hy2_up_mbps = get_u64(proxy, "up");
    node.hy2_down_mbps = get_u64(proxy, "down");
    Some(node)
}

fn parse_clash_ssr(proxy: &Mapping, name: &str) -> Result<ProxyNode, String> {
    let server = get_required_str(proxy, "server", "Clash SSR proxy server is required")?;
    let port = get_required_u16(proxy, "port", "Clash SSR proxy port is required")?;
    let method = get_required_str(proxy, "cipher", "Clash SSR proxy cipher is required")?;
    let password = get_required_str(proxy, "password", "Clash SSR proxy password is required")?;
    let mut node = ProxyNode::default_with(ProxyProtocol::ShadowsocksR, name, server, port);
    node.method = method.to_string();
    node.password = password.to_string();
    node.ssr_protocol = get_str(proxy, "protocol").unwrap_or("origin").to_string();
    node.ssr_protocol_param = get_str(proxy, "protocol-param")
        .or_else(|| get_str(proxy, "protocol_param"))
        .unwrap_or("")
        .to_string();
    node.ssr_obfs = get_str(proxy, "obfs").unwrap_or("plain").to_string();
    node.ssr_obfs_param = get_str(proxy, "obfs-param")
        .or_else(|| get_str(proxy, "obfs_param"))
        .unwrap_or("")
        .to_string();
    Ok(node)
}

fn parse_clash_anytls(proxy: &Mapping, name: &str, server: &str, port: u16) -> Option<ProxyNode> {
    let password = get_str(proxy, "password")?;
    let mut node = ProxyNode::default_with(ProxyProtocol::Anytls, name, server, port);
    node.password = password.to_string();
    node.tls_enabled = true;
    node.tls_insecure = get_bool(proxy, "skip-cert-verify");
    node.tls_fingerprint = get_str(proxy, "client-fingerprint")
        .unwrap_or("")
        .to_string();
    node.tls_alpn = get_alpn(proxy);

    apply_transport_fields(&mut node, proxy);

    let explicit_sni = get_explicit_sni(proxy);
    node.tls_sni = if !explicit_sni.is_empty() {
        explicit_sni
    } else if node.transport == TransportType::Ws && !node.transport_host.is_empty() {
        node.transport_host.clone()
    } else {
        server.to_string()
    };

    Some(node)
}

#[cfg(test)]
mod tests {
    use super::super::types::{ProxyProtocol, TransportType};
    use super::parse_clash_yaml;

    #[test]
    fn legacy_websocket_options_are_preserved_and_conflicts_rejected() {
        let yaml = "proxies:\n  - name: 日本-优化\n    type: trojan\n    server: example.com\n    port: 443\n    password: secret\n    network: ws\n    ws-path: /legacy\n    ws-headers: {Host: cdn.example.com}";
        let nodes = parse_clash_yaml(yaml).unwrap();
        let node = &nodes[0];
        assert_eq!(node.transport, TransportType::Ws);
        assert_eq!(node.transport_path, "/legacy");
        assert_eq!(node.transport_host, "cdn.example.com");
        let conflict = format!("{yaml}\n    ws-opts: {{path: /other}}");
        assert!(parse_clash_yaml(&conflict).unwrap_err().contains("冲突"));
        let wrong_network = yaml.replace("network: ws", "network: tcp");
        assert!(parse_clash_yaml(&wrong_network).is_err());
        let bad_headers = yaml.replace("Host: cdn.example.com", "Custom: value");
        assert!(parse_clash_yaml(&bad_headers).is_err());
    }

    #[test]
    fn test_parse_clash_vmess_ws_tls_preserves_transport_and_tls_fields() {
        let yaml = r#"
proxies:
  - name: Test-VMess
    type: vmess
    server: vmess.example.com
    port: 443
    uuid: 11111111-1111-1111-1111-111111111111
    alterId: 7
    cipher: auto
    tls: true
    servername: sni.example.com
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

        let nodes = parse_clash_yaml(yaml).unwrap();
        assert_eq!(nodes.len(), 1);

        let node = &nodes[0];
        assert_eq!(node.protocol, ProxyProtocol::Vmess);
        assert_eq!(node.name, "Test-VMess");
        assert_eq!(node.server, "vmess.example.com");
        assert_eq!(node.port, 443);
        assert_eq!(node.uuid, "11111111-1111-1111-1111-111111111111");
        assert_eq!(node.alter_id, 7);
        assert_eq!(node.method, "auto");
        assert_eq!(node.transport, TransportType::Ws);
        assert_eq!(node.transport_path, "/ws");
        assert_eq!(node.transport_host, "cdn.example.com");
        assert!(node.tls_enabled);
        assert_eq!(node.tls_sni, "sni.example.com");
        assert_eq!(node.tls_fingerprint, "chrome");
        assert_eq!(node.tls_alpn, vec!["h2", "http/1.1"]);
    }

    #[test]
    fn test_parse_clash_vless_reality_preserves_reality_and_grpc_fields() {
        let yaml = r#"
proxies:
  - name: Test-VLESS-Reality
    type: vless
    server: vless.example.com
    port: 8443
    uuid: 22222222-2222-2222-2222-222222222222
    flow: xtls-rprx-vision
    tls: true
    servername: reality.example.com
    client-fingerprint: firefox
    alpn: h2,http/1.1
    network: grpc
    grpc-opts:
      grpc-service-name: grpc-service
    reality-opts:
      public-key: pubkey123
      short-id: 1a2b
"#;

        let nodes = parse_clash_yaml(yaml).unwrap();
        assert_eq!(nodes.len(), 1);

        let node = &nodes[0];
        assert_eq!(node.protocol, ProxyProtocol::Vless);
        assert_eq!(node.flow, "xtls-rprx-vision");
        assert_eq!(node.transport, TransportType::Grpc);
        assert_eq!(node.transport_service, "grpc-service");
        assert_eq!(node.transport_path, "");
        assert!(node.tls_enabled);
        assert_eq!(node.tls_sni, "reality.example.com");
        assert_eq!(node.tls_fingerprint, "firefox");
        assert_eq!(node.tls_alpn, vec!["h2", "http/1.1"]);
        assert!(node.reality_enabled);
        assert_eq!(node.reality_public_key, "pubkey123");
        assert_eq!(node.reality_short_id, "1a2b");
    }

    #[test]
    fn test_parse_clash_trojan_ws_preserves_tls_and_transport_fields() {
        let yaml = r#"
proxies:
  - name: Test-Trojan
    type: trojan
    server: trojan.example.com
    port: 443
    password: pass123
    sni: tls.example.com
    skip-cert-verify: true
    client-fingerprint: chrome
    alpn:
      - h2
    network: ws
    ws-opts:
      path: /trojan
      headers:
        Host: cdn.example.com
"#;

        let nodes = parse_clash_yaml(yaml).unwrap();
        assert_eq!(nodes.len(), 1);

        let node = &nodes[0];
        assert_eq!(node.protocol, ProxyProtocol::Trojan);
        assert_eq!(node.password, "pass123");
        assert_eq!(node.transport, TransportType::Ws);
        assert_eq!(node.transport_path, "/trojan");
        assert_eq!(node.transport_host, "cdn.example.com");
        assert!(node.tls_enabled);
        assert_eq!(node.tls_sni, "tls.example.com");
        assert!(node.tls_insecure);
        assert_eq!(node.tls_fingerprint, "chrome");
        assert_eq!(node.tls_alpn, vec!["h2"]);
    }

    #[test]
    fn test_parse_clash_ss_preserves_plugin_fields() {
        let yaml = r#"
proxies:
  - name: Test-SS
    type: ss
    server: ss.example.com
    port: 8388
    cipher: aes-256-gcm
    password: ss-pass
    plugin: v2ray-plugin
    plugin-opts: mode=websocket;host=cdn.example.com
"#;

        let nodes = parse_clash_yaml(yaml).unwrap();
        assert_eq!(nodes.len(), 1);

        let node = &nodes[0];
        assert_eq!(node.protocol, ProxyProtocol::Shadowsocks);
        assert_eq!(node.method, "aes-256-gcm");
        assert_eq!(node.password, "ss-pass");
        assert_eq!(node.ss_plugin, "v2ray-plugin");
        assert_eq!(node.ss_plugin_opts, "mode=websocket;host=cdn.example.com");
    }

    #[test]
    fn test_parse_clash_hysteria2_preserves_obfs_bandwidth_and_tls_fields() {
        let yaml = r#"
proxies:
  - name: Test-HY2
    type: hysteria2
    server: hy2.example.com
    port: 8443
    password: hy2-pass
    servername: hy2-sni.example.com
    skip-cert-verify: true
    alpn:
      - h3
      - h2
    obfs: salamander
    obfs-password: obfs-pass
    up: 50
    down: 120
"#;

        let nodes = parse_clash_yaml(yaml).unwrap();
        assert_eq!(nodes.len(), 1);

        let node = &nodes[0];
        assert_eq!(node.protocol, ProxyProtocol::Hysteria2);
        assert_eq!(node.password, "hy2-pass");
        assert!(node.tls_enabled);
        assert_eq!(node.tls_sni, "hy2-sni.example.com");
        assert!(node.tls_insecure);
        assert_eq!(node.tls_alpn, vec!["h3", "h2"]);
        assert_eq!(node.hy2_obfs_type, "salamander");
        assert_eq!(node.hy2_obfs_password, "obfs-pass");
        assert_eq!(node.hy2_up_mbps, Some(50));
        assert_eq!(node.hy2_down_mbps, Some(120));
    }

    #[test]
    fn test_parse_clash_ssr_preserves_ssr_fields() {
        let yaml = r#"
proxies:
  - name: Test-SSR
    type: ssr
    server: ssr.example.com
    port: 9443
    cipher: aes-256-cfb
    password: ssr-pass
    protocol: auth_sha1_v4
    protocol-param: proto-param
    obfs: tls1.2_ticket_auth
    obfs-param: obfs-host.example.com
"#;

        let nodes = parse_clash_yaml(yaml).unwrap();
        assert_eq!(nodes.len(), 1);

        let node = &nodes[0];
        assert_eq!(node.protocol, ProxyProtocol::ShadowsocksR);
        assert_eq!(node.name, "Test-SSR");
        assert_eq!(node.server, "ssr.example.com");
        assert_eq!(node.port, 9443);
        assert_eq!(node.method, "aes-256-cfb");
        assert_eq!(node.password, "ssr-pass");
        assert_eq!(node.ssr_protocol, "auth_sha1_v4");
        assert_eq!(node.ssr_protocol_param, "proto-param");
        assert_eq!(node.ssr_obfs, "tls1.2_ticket_auth");
        assert_eq!(node.ssr_obfs_param, "obfs-host.example.com");
    }

    #[test]
    fn test_parse_clash_anytls_defaults_tls_and_sni_when_flag_omitted() {
        let yaml = r#"
proxies:
  - name: anytls-no-tls-flag
    type: anytls
    server: anytls.example.com
    port: "443"
    password: anytls-pass
    network: ws
    ws-opts:
      path: /ws
      headers:
        Host: cdn.anytls.example.com
"#;

        let nodes = parse_clash_yaml(yaml).unwrap();
        assert_eq!(nodes.len(), 1);
        let node = &nodes[0];

        assert_eq!(node.protocol, ProxyProtocol::Anytls);
        assert!(node.tls_enabled);
        assert_eq!(node.tls_sni, "cdn.anytls.example.com");
        assert_eq!(node.transport, TransportType::Ws);
        assert_eq!(node.transport_path, "/ws");
        assert_eq!(node.transport_host, "cdn.anytls.example.com");
    }

    #[test]
    fn test_parse_clash_anytls_preserves_tls_and_ws_fields() {
        let yaml = r#"
proxies:
  - name: Test-AnyTLS
    type: anytls
    server: anytls.example.com
    port: 443
    password: anytls-pass
    tls: true
    servername: tls.example.com
    skip-cert-verify: true
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

        let nodes = parse_clash_yaml(yaml).unwrap();
        assert_eq!(nodes.len(), 1);

        let node = &nodes[0];
        assert_eq!(node.protocol, ProxyProtocol::Anytls);
        assert_eq!(node.name, "Test-AnyTLS");
        assert_eq!(node.server, "anytls.example.com");
        assert_eq!(node.port, 443);
        assert_eq!(node.password, "anytls-pass");
        assert_eq!(node.transport, TransportType::Ws);
        assert_eq!(node.transport_path, "/ws");
        assert_eq!(node.transport_host, "cdn.example.com");
        assert!(node.tls_enabled);
        assert_eq!(node.tls_sni, "tls.example.com");
        assert!(node.tls_insecure);
        assert_eq!(node.tls_fingerprint, "chrome");
        assert_eq!(node.tls_alpn, vec!["h2", "http/1.1"]);
    }

    #[test]
    fn test_parse_clash_yaml_rejects_unsupported_and_incomplete_entries() {
        let yaml = r#"
proxies:
  - name: Unsupported
    type: socks5
    server: socks.example.com
    port: 1080
  - name: Incomplete-VMess
    type: vmess
    server: bad.example.com
    port: 443
  - name: Valid-SS
    type: ss
    server: ss.example.com
    port: 8388
    cipher: aes-128-gcm
    password: good-pass
"#;

        let error = parse_clash_yaml(yaml).unwrap_err();
        assert!(error.contains("第 1 个节点"));
        assert!(error.contains("Unsupported"));
        assert!(error.contains("type"));
    }

    #[test]
    fn rejects_malformed_and_incomplete_nodes_with_context() {
        for entry in [
            "not-an-object",
            "{name: missing-type}",
            "{name: missing-server, type: trojan, port: 443, password: secret}",
            "{name: missing-uuid, type: vless, server: example.com, port: 443}",
            "{name: bad-port, type: trojan, server: example.com, port: 0, password: secret}",
        ] {
            let error = parse_clash_yaml(&format!("proxies:\n  - {entry}")).unwrap_err();
            assert!(error.contains("第 1 个节点"));
            assert!(!error.contains("secret"));
        }
    }

    #[test]
    fn rejects_lossy_transport_options() {
        for option in [
            "network: xhttp",
            "smux: {enabled: true}",
            "packet-encoding: xudp",
            "dialer-proxy: upstream",
            "ws-opts: {path: /ws, max-early-data: 2048}",
            "ws-opts: {headers: {Custom: value}}",
        ] {
            let yaml = format!(
                "proxies:\n  - name: test\n    type: vless\n    server: example.com\n    port: 443\n    uuid: 11111111-1111-1111-1111-111111111111\n    {option}"
            );
            assert!(parse_clash_yaml(&yaml).is_err(), "{option}");
        }
    }

    #[test]
    fn rejects_http_obfuscation_instead_of_changing_it_to_http2() {
        for tls in [false, true] {
            let yaml = format!(
                "proxies:\n  - name: http\n    type: vless\n    server: example.com\n    port: 443\n    uuid: 11111111-1111-1111-1111-111111111111\n    tls: {tls}\n    network: http\n    http-opts:\n      path: [/stream]\n      headers:\n        Host: [cdn.example.com]"
            );
            let error = parse_clash_yaml(&yaml).unwrap_err();
            assert!(error.contains("HTTP/1.1 TCP 伪装"));
        }
    }

    #[test]
    fn preserves_tls_h2_path_and_authority_without_changing_sni() {
        let yaml = "proxies:\n  - name: h2\n    type: vless\n    server: example.com\n    port: 443\n    uuid: 11111111-1111-1111-1111-111111111111\n    tls: true\n    network: h2\n    h2-opts:\n      path: /stream\n      host: [cdn.example.com]";
        let nodes = parse_clash_yaml(yaml).unwrap();
        let node = &nodes[0];
        assert_eq!(node.transport, TransportType::Http);
        assert_eq!(node.transport_host, "cdn.example.com");
        assert_eq!(node.tls_sni, "example.com");
        let outbound = super::super::gen_singbox::node_to_singbox_outbound(node).unwrap();
        assert_eq!(outbound["transport"]["host"][0], "cdn.example.com");
        assert_eq!(outbound["transport"]["path"], "/stream");
        assert!(
            parse_clash_yaml(&yaml.replace("tls: true", "tls: false"))
                .unwrap_err()
                .contains("明文 HTTP/2")
        );
        assert!(
            parse_clash_yaml(
                &yaml.replace("[cdn.example.com]", "[cdn.example.com, other.example.com]")
            )
            .is_err()
        );
    }

    #[test]
    fn translates_obfs_mapping_to_sip003_plugin_options() {
        let yaml = "proxies:\n  - name: obfs\n    type: ss\n    server: example.com\n    port: 8388\n    cipher: aes-128-gcm\n    password: secret\n    plugin: obfs\n    plugin-opts:\n      mode: http\n      host: cdn.example.com";
        let node = &parse_clash_yaml(yaml).unwrap()[0];
        assert_eq!(node.ss_plugin, "obfs-local");
        assert!(node.ss_plugin_opts.contains("obfs=http"));
        assert!(node.ss_plugin_opts.contains("obfs-host=cdn.example.com"));
    }

    #[test]
    fn test_parse_clash_yaml_returns_error_for_invalid_yaml() {
        let err = parse_clash_yaml("proxies: [").unwrap_err();

        assert!(err.contains("Failed to parse Clash YAML"));
    }
}
