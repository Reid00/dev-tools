use std::{process::Stdio, time::Duration};

use serde::Serialize;
use serde_json::Value;
use tokio::{io::AsyncWriteExt, process::Command, sync::Semaphore, time::timeout};

static CHECK_SLOTS: Semaphore = Semaphore::const_new(4);

#[derive(Debug, Serialize)]
pub struct ValidationInfo {
    pub engine: &'static str,
    pub version: String,
    pub checked: bool,
}

#[derive(Debug)]
pub struct ValidationError {
    pub unavailable: bool,
    pub message: String,
    pub outbound_index: Option<usize>,
}

impl ValidationError {
    fn unavailable(message: impl Into<String>) -> Self {
        Self {
            unavailable: true,
            message: message.into(),
            outbound_index: None,
        }
    }

    fn invalid(message: impl Into<String>) -> Self {
        Self {
            unavailable: false,
            message: message.into(),
            outbound_index: None,
        }
    }
}

pub async fn check_config(config: &Value) -> Result<ValidationInfo, ValidationError> {
    validate_references(config).map_err(ValidationError::invalid)?;
    reject_local_resources(config).map_err(ValidationError::invalid)?;
    let _slot = CHECK_SLOTS
        .try_acquire()
        .map_err(|_| ValidationError::unavailable("配置校验繁忙，请稍后重试"))?;
    let binary = std::env::var_os("SING_BOX_BINARY").unwrap_or_else(|| "sing-box".into());
    let version_output = timeout(Duration::from_secs(5), Command::new(&binary)
        .arg("version").kill_on_drop(true).output()).await
        .map_err(|_| ValidationError::unavailable("sing-box 版本检测超时"))?
        .map_err(|_| ValidationError::unavailable(
            "未找到可执行的 sing-box 内核，无法保证配置有效。请安装 sing-box 1.14.x 并加入 PATH，或设置 SING_BOX_BINARY 为其绝对路径；Docker 镜像已内置内核。"))?;
    let version_text = String::from_utf8_lossy(&version_output.stdout);
    let version = version_text
        .lines()
        .find_map(|line| line.strip_prefix("sing-box version "))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            ValidationError::unavailable("无法识别 sing-box 内核版本，请使用官方 1.14.x 稳定版")
        })?;
    if !version_output.status.success() || !version.starts_with("1.14.") || version.contains('-') {
        return Err(ValidationError::unavailable(
            "配置面向 sing-box 1.14.x 稳定版，请更换校验内核；不支持旧版本或预发行版",
        ));
    }
    let bytes = serde_json::to_vec(config)
        .map_err(|_| ValidationError::invalid("无法序列化 sing-box 配置"))?;
    let mut child = Command::new(&binary)
        .args(["check", "-c", "stdin", "--disable-color"])
        .env_remove("ENABLE_DEPRECATED_LEGACY_DNS_SERVERS")
        .env_remove("ENABLE_DEPRECATED_SPECIAL_OUTBOUNDS")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| {
            ValidationError::unavailable(
                "无法启动 sing-box 配置校验，请检查 SING_BOX_BINARY 和执行权限",
            )
        })?;
    let mut stdin = child.stdin.take().expect("piped stdin");
    let output = timeout(Duration::from_secs(15), async move {
        let write = async move {
            stdin.write_all(&bytes).await?;
            stdin.shutdown().await
        };
        let (write_result, output) = tokio::join!(write, child.wait_with_output());
        let output = output?;
        if output.status.success() {
            write_result?;
        }
        Ok::<_, std::io::Error>(output)
    })
    .await
    .map_err(|_| ValidationError::unavailable("sing-box 配置校验超过 15 秒，请稍后重试"))?
    .map_err(|_| ValidationError::unavailable("sing-box 配置校验进程异常退出"))?;
    if !output.status.success() {
        let diagnostic = String::from_utf8_lossy(&output.stderr);
        let detail = redact_diagnostic(&diagnostic, config);
        let mut error = ValidationError::invalid(format!(
            "sing-box {version} 校验失败，未生成订阅。请修正节点或模板：\n{detail}"
        ));
        error.outbound_index = diagnostic_outbound_index(&diagnostic);
        return Err(error);
    }
    Ok(ValidationInfo {
        engine: "sing-box",
        version: version.to_string(),
        checked: true,
    })
}

fn diagnostic_outbound_index(message: &str) -> Option<usize> {
    let diagnostic = message.lines().find(|line| line.contains("FATAL"))?;
    let detail = diagnostic.split_once("] ")?.1;
    let index = detail
        .strip_prefix("initialize outbound[")
        .or_else(|| detail.strip_prefix("decode config at stdin: outbounds["))?;
    index.split_once(']')?.0.parse().ok()
}

fn redact_diagnostic(message: &str, config: &Value) -> String {
    fn secrets(value: &Value, found: &mut Vec<String>) {
        match value {
            Value::Object(map) => {
                for (key, value) in map {
                    if matches!(
                        key.as_str(),
                        "password"
                            | "uuid"
                            | "public_key"
                            | "short_id"
                            | "secret"
                            | "url"
                            | "token"
                    ) && let Some(value) = value.as_str().filter(|v| !v.is_empty())
                    {
                        found.push(value.to_string());
                    }
                    secrets(value, found);
                }
            }
            Value::Array(items) => {
                for item in items {
                    secrets(item, found);
                }
            }
            _ => {}
        }
    }
    let mut found = Vec::new();
    secrets(config, &mut found);
    found.sort_by_key(|value| std::cmp::Reverse(value.len()));
    let mut message = message.to_string();
    for secret in found {
        message = message.replace(&secret, "[已隐藏]");
    }
    message
        .chars()
        .filter(|c| !c.is_control() || *c == '\n')
        .take(2000)
        .collect()
}

fn reject_local_resources(value: &Value) -> Result<(), String> {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                if key.ends_with("_path")
                    || matches!(key.as_str(), "path" | "external_ui")
                        && map.get("type").and_then(Value::as_str) == Some("local")
                {
                    return Err(format!(
                        "模板不允许引用服务器本地文件：{key}，请使用内联配置或远程资源"
                    ));
                }
                reject_local_resources(value)?;
            }
        }
        Value::Array(items) => {
            for item in items {
                reject_local_resources(item)?;
            }
        }
        _ => {}
    }
    Ok(())
}

pub fn validate_references(config: &Value) -> Result<(), String> {
    let outbounds = config["outbounds"]
        .as_array()
        .ok_or("配置 outbounds 必须是数组")?;
    if outbounds.is_empty() {
        return Err("配置没有出站节点".to_string());
    }
    let mut tags = std::collections::HashMap::new();
    for (index, outbound) in outbounds.iter().enumerate() {
        let tag = outbound["tag"]
            .as_str()
            .filter(|tag| !tag.trim().is_empty())
            .ok_or_else(|| format!("outbounds[{}] 缺少非空 tag", index + 1))?;
        if tags.insert(tag, index).is_some() {
            return Err(format!("出站 tag 重复：{tag}"));
        }
    }
    let mut edges = vec![Vec::new(); outbounds.len()];
    for (index, outbound) in outbounds.iter().enumerate() {
        let mut references = Vec::new();
        if matches!(outbound["type"].as_str(), Some("selector" | "urltest")) {
            let members = outbound["outbounds"]
                .as_array()
                .filter(|v| !v.is_empty())
                .ok_or_else(|| format!("出站 {} 的节点组不能为空", outbound["tag"]))?;
            for member in members {
                references.push(member.as_str().ok_or("节点组成员必须是字符串")?);
            }
            if let Some(default) = outbound.get("default") {
                let default = default.as_str().ok_or("节点组 default 必须是字符串")?;
                if !references.contains(&default) {
                    return Err(format!(
                        "节点组 {} 的 default 不在成员列表中",
                        outbound["tag"]
                    ));
                }
            }
        }
        if let Some(detour) = outbound.get("detour") {
            references.push(detour.as_str().ok_or("出站 detour 必须是字符串")?);
        }
        for reference in references {
            let target = tags.get(reference).ok_or_else(|| {
                format!("出站 {} 引用了不存在的节点：{reference}", outbound["tag"])
            })?;
            edges[index].push(*target);
        }
    }
    fn visit(index: usize, edges: &[Vec<usize>], marks: &mut [u8]) -> Result<(), String> {
        if marks[index] == 1 {
            return Err("出站节点组或 detour 存在循环引用".to_string());
        }
        if marks[index] == 2 {
            return Ok(());
        }
        marks[index] = 1;
        for &next in &edges[index] {
            visit(next, edges, marks)?;
        }
        marks[index] = 2;
        Ok(())
    }
    let mut marks = vec![0; edges.len()];
    for index in 0..edges.len() {
        visit(index, &edges, &mut marks)?;
    }
    if let Some(final_tag) = config["route"].get("final") {
        let tag = final_tag.as_str().ok_or("route.final 必须是字符串")?;
        if !tags.contains_key(tag) {
            return Err(format!("route.final 引用了不存在的出站：{tag}"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn native_diagnostics_only_attribute_explicit_outbound_errors() {
        assert_eq!(
            diagnostic_outbound_index("FATAL[0000] initialize outbound[3]: invalid public_key"),
            Some(3)
        );
        assert_eq!(
            diagnostic_outbound_index(
                "FATAL[0000] decode config at stdin: outbounds[5].tls: unknown field"
            ),
            Some(5)
        );
        assert_eq!(
            diagnostic_outbound_index("FATAL[0000] initialize inbound[3]: invalid port"),
            None
        );
        assert_eq!(
            diagnostic_outbound_index("WARN[0000] initialize outbound[3]: unsupported"),
            None
        );
        assert_eq!(
            diagnostic_outbound_index("FATAL[0000] initialize router: outbound[3] not found"),
            None
        );
    }

    #[test]
    fn rejects_missing_members_duplicate_tags_and_cycles() {
        for outbounds in [
            json!([{"tag":"a","type":"selector","outbounds":["missing"]}]),
            json!([{"tag":"a","type":"direct"},{"tag":"a","type":"direct"}]),
            json!([{"tag":"a","type":"selector","outbounds":["b"]},{"tag":"b","type":"selector","outbounds":["a"]}]),
            json!([{"tag":"a","type":"urltest","outbounds":[]}]),
            json!([{"tag":"a","type":"selector","outbounds":["b"],"default":"c"},{"tag":"b","type":"direct"}]),
        ] {
            assert!(validate_references(&json!({"outbounds":outbounds})).is_err());
        }
    }

    #[test]
    fn accepts_valid_references_and_redacts_credentials() {
        let config = json!({"outbounds":[{"tag":"proxy","type":"selector","outbounds":["node"]},{"tag":"node","type":"trojan","password":"private-password"}],"route":{"final":"proxy"}});
        validate_references(&config).unwrap();
        assert_eq!(
            redact_diagnostic("bad private-password", &config),
            "bad [已隐藏]"
        );
    }

    #[test]
    fn rejects_server_file_access_but_allows_transport_paths() {
        assert!(
            reject_local_resources(&json!({"tls":{"certificate_path":"/etc/passwd"}})).is_err()
        );
        assert!(reject_local_resources(&json!({"type":"local","path":"/etc/passwd"})).is_err());
        reject_local_resources(&json!({"transport":{"type":"ws","path":"/ws"}})).unwrap();
    }

    #[tokio::test]
    #[ignore = "requires official sing-box 1.14.x; set SING_BOX_BINARY and run with --ignored"]
    async fn official_kernel_accepts_every_builtin_template() {
        assert!(
            std::env::var_os("SING_BOX_BINARY").is_some(),
            "请设置 SING_BOX_BINARY"
        );
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        let vmess = STANDARD.encode(
            json!({
                "v":"2", "ps":"VMess", "add":"example.com", "port":443,
                "id":"11111111-1111-1111-1111-111111111111", "aid":0,
                "net":"ws", "path":"/ws", "host":"cdn.example.com", "tls":"tls"
            })
            .to_string(),
        );
        let sources = [
            "trojan://secret@example.com:443#Trojan".to_string(),
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls#VLESS".to_string(),
            format!("vmess://{vmess}"),
            "ss://aes-128-gcm:secret@example.com:8388#SS".to_string(),
            "hy2://secret@example.com:443#Hysteria2".to_string(),
            "anytls://secret@example.com:443#AnyTLS".to_string(),
            "ss://aes-128-gcm:secret@example.com:8388?plugin=v2ray-plugin%3Bmode%3Dwebsocket%3Bhost%3Dcdn.example.com#SSPlugin".to_string(),
            "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=reality&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=11#REALITY".to_string(),
        ];
        for source in sources {
            let nodes = super::super::parser::parse_subscription_content(&source).unwrap();
            for template in super::super::template::builtin_templates() {
                let text = super::super::template::builtin_template_content(template.id).unwrap();
                let config = super::super::render::render_template(text, &nodes).unwrap();
                let result = check_config(&config).await.unwrap_or_else(|err| {
                    panic!("{} / {}: {}", nodes[0].name, template.id, err.message)
                });
                assert!(result.checked);
            }
        }
        let invalid = json!({"outbounds":[{
            "type":"trojan", "tag":"invalid", "server":"example.com", "server_port":443,
            "password":"private-password", "tls":{"enabled":true,"utls":{"enabled":true,"fingerprint":"private-password"}}
        }]});
        let error = check_config(&invalid).await.unwrap_err();
        assert!(!error.unavailable);
        assert!(error.message.contains("校验失败"));
        assert!(error.message.contains("[已隐藏]"));
        assert!(!error.message.contains("private-password"));
    }
}
