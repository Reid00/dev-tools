#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyProtocol {
    Vmess,
    Vless,
    Trojan,
    Shadowsocks,
    ShadowsocksR,
    Hysteria2,
    Anytls,
}

impl ProxyProtocol {
    pub const fn protocol_str(&self) -> &'static str {
        match self {
            Self::Vmess => "vmess",
            Self::Vless => "vless",
            Self::Trojan => "trojan",
            Self::Shadowsocks => "shadowsocks",
            Self::ShadowsocksR => "shadowsocksr",
            Self::Hysteria2 => "hysteria2",
            Self::Anytls => "anytls",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportType {
    Tcp,
    Ws,
    Grpc,
    Http,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyNode {
    pub name: String,
    pub server: String,
    pub port: u16,
    pub protocol: ProxyProtocol,
    pub password: String,
    pub uuid: String,
    pub alter_id: u32,
    pub method: String,
    pub flow: String,
    pub transport: TransportType,
    pub transport_path: String,
    pub transport_host: String,
    pub transport_service: String,
    pub tls_enabled: bool,
    pub tls_sni: String,
    pub tls_insecure: bool,
    pub tls_fingerprint: String,
    pub tls_alpn: Vec<String>,
    pub reality_enabled: bool,
    pub reality_public_key: String,
    pub reality_short_id: String,
    pub ss_plugin: String,
    pub ss_plugin_opts: String,
    pub ssr_protocol: String,
    pub ssr_protocol_param: String,
    pub ssr_obfs: String,
    pub ssr_obfs_param: String,
    pub hy2_obfs_type: String,
    pub hy2_obfs_password: String,
    pub hy2_up_mbps: Option<u64>,
    pub hy2_down_mbps: Option<u64>,
}

impl ProxyNode {
    pub fn default_with(protocol: ProxyProtocol, name: &str, server: &str, port: u16) -> Self {
        Self {
            name: name.to_string(),
            server: server.to_string(),
            port,
            protocol,
            password: String::new(),
            uuid: String::new(),
            alter_id: 0,
            method: String::new(),
            flow: String::new(),
            transport: TransportType::Tcp,
            transport_path: String::new(),
            transport_host: String::new(),
            transport_service: String::new(),
            tls_enabled: false,
            tls_sni: String::new(),
            tls_insecure: false,
            tls_fingerprint: String::new(),
            tls_alpn: Vec::new(),
            reality_enabled: false,
            reality_public_key: String::new(),
            reality_short_id: String::new(),
            ss_plugin: String::new(),
            ss_plugin_opts: String::new(),
            ssr_protocol: String::new(),
            ssr_protocol_param: String::new(),
            ssr_obfs: String::new(),
            ssr_obfs_param: String::new(),
            hy2_obfs_type: String::new(),
            hy2_obfs_password: String::new(),
            hy2_up_mbps: None,
            hy2_down_mbps: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ProxyNode, ProxyProtocol, TransportType};

    #[test]
    fn test_default_proxy_node() {
        let node = ProxyNode::default_with(ProxyProtocol::Vmess, "demo", "example.com", 443);

        assert_eq!(node.name, "demo");
        assert_eq!(node.server, "example.com");
        assert_eq!(node.port, 443);
        assert!(matches!(node.protocol, ProxyProtocol::Vmess));
        assert!(matches!(node.transport, TransportType::Tcp));
        assert!(!node.tls_enabled);
        assert_eq!(node.tls_sni, "");
        assert!(!node.reality_enabled);
        assert_eq!(node.reality_public_key, "");
        assert_eq!(node.reality_short_id, "");
        assert_eq!(node.ss_plugin, "");
        assert_eq!(node.ss_plugin_opts, "");
    }

    #[test]
    fn test_all_protocol_strs() {
        assert_eq!(ProxyProtocol::Vmess.protocol_str(), "vmess");
        assert_eq!(ProxyProtocol::Vless.protocol_str(), "vless");
        assert_eq!(ProxyProtocol::Trojan.protocol_str(), "trojan");
        assert_eq!(ProxyProtocol::Shadowsocks.protocol_str(), "shadowsocks");
        assert_eq!(ProxyProtocol::ShadowsocksR.protocol_str(), "shadowsocksr");
        assert_eq!(ProxyProtocol::Hysteria2.protocol_str(), "hysteria2");
        assert_eq!(ProxyProtocol::Anytls.protocol_str(), "anytls");
    }
}
