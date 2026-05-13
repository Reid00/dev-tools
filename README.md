# Dev Tools - 开发者工具箱

一个基于 Rust + Axum 构建的轻量级开发者工具箱，提供常用的开发工具，通过 Web UI 进行交互。

当前版本：**v0.5.0**

## 功能概览

| 工具 | 描述 |
|------|------|
| 🕐 时间转换 | 时间戳与日期时间互转、时区转换、格式转换 |
| 📄 JSON 格式化 | JSON 格式化、压缩、校验、键排序 |
| 🐍 Dict 转 JSON | Python Dict 字符串转 JSON (支持 True/False/None、单引号、元组等) |
| 🌐 翻译工具 | 中英文互译 (基于阿里云机器翻译) |
| ✍️ Markdown 渲染 | Markdown 实时预览、服务端渲染、工具栏快捷操作 |
| 🔌 HTTP 请求 | HTTP 请求构建器 (类似轻量级 Postman) |
| 📡 订阅转换 | URL 订阅转换为 sing-box 配置，支持内置/远程模板 |

## 快速开始

### 环境要求

- Rust 1.90+ (edition 2024)
- Cargo

### 安装运行

```bash
# 克隆项目
git clone https://github.com/yourname/dev-tools.git
cd dev-tools

# 配置阿里云机器翻译凭证
export ALIBABA_CLOUD_ACCESS_KEY_ID='your-access-key-id'
export ALIBABA_CLOUD_ACCESS_KEY_SECRET='your-access-key-secret'

# 运行开发服务器
cargo run

# 或构建发布版本
cargo build --release
./target/release/dev-tools
```

服务启动后访问: **http://localhost:3000**

## Docker 部署

### 方式一：Docker Compose (推荐)

```bash
# 配置阿里云机器翻译凭证
export ALIBABA_CLOUD_ACCESS_KEY_ID='your-access-key-id'
export ALIBABA_CLOUD_ACCESS_KEY_SECRET='your-access-key-secret'

# 构建并启动
docker compose up -d

# 查看日志
docker compose logs -f

# 停止服务
docker compose down
```

### 方式二：Docker 直接构建

```bash
# 构建镜像
docker build -t dev-tools:latest .

# 运行容器
docker run -d \
  --name dev-tools \
  -p 3000:3000 \
  -e RUST_LOG=info \
  -e TZ=Asia/Shanghai \
  -e ALIBABA_CLOUD_ACCESS_KEY_ID='your-access-key-id' \
  -e ALIBABA_CLOUD_ACCESS_KEY_SECRET='your-access-key-secret' \
  --restart unless-stopped \
  dev-tools:latest
```

### 方式三：使用预构建镜像

```bash
# 拉取镜像 (如果已发布到 Docker Hub)
docker pull yourname/dev-tools:latest

# 运行容器
docker run -d \
  --name dev-tools \
  -p 3000:3000 \
  -e ALIBABA_CLOUD_ACCESS_KEY_ID='your-access-key-id' \
  -e ALIBABA_CLOUD_ACCESS_KEY_SECRET='your-access-key-secret' \
  --restart unless-stopped \
  yourname/dev-tools:latest
```

### Docker 配置说明

| 配置项 | 说明 | 默认值 |
|--------|------|--------|
| `-p 3000:3000` | 端口映射，格式为 `主机端口:容器端口` | 3000 |
| `-e RUST_LOG` | 日志级别 (debug/info/warn/error) | info |
| `-e TZ` | 时区设置 | Asia/Shanghai |
| `--restart unless-stopped` | 容器自动重启策略 | - |

### Docker 常用命令

```bash
# 查看容器状态
docker ps

# 查看实时日志
docker logs -f dev-tools

# 进入容器
docker exec -it dev-tools sh

# 重启容器
docker restart dev-tools

# 停止并删除容器
docker rm -f dev-tools

# 删除镜像
docker rmi dev-tools:latest
```

## 工具详解

### 1. 时间转换

- **当前时间**: 实时显示 Unix 秒/毫秒、本地时间、UTC、ISO 8601、星期
- **时间戳 → 日期**: 支持秒/毫秒级时间戳，可选时区
- **日期 → 时间戳**: 支持多种日期格式输入
- **时区转换**: 支持全球主要时区互转
- **格式转换**: 标准、斜线、点、紧凑、中文、ISO 8601 等格式

### 2. JSON 格式化

- 格式化 (可选缩进: 2/4 空格)
- 压缩/Minify
- JSON 校验 (显示错误位置)
- 键排序
- 支持 `#` 注释
- 统计信息: 键数、深度、大小

### 3. Python Dict 转 JSON

将 Python 风格的字典字符串转换为标准 JSON:

```python
# 输入
{'name': 'test', 'active': True, 'data': None, 'items': (1, 2, 3)}

# 输出
{
  "name": "test",
  "active": true,
  "data": null,
  "items": [1, 2, 3]
}
```

支持特性:
- `True`/`False`/`None` → `true`/`false`/`null`
- 单引号 → 双引号
- 元组 `()` → 数组 `[]`
- 末尾逗号自动处理

### 4. 翻译工具

- 自动检测源语言
- 自动检测目标语言 (中文→英文，英文→中文)
- 中英文互译
- 字符统计
- 快速交换语言

### 5. Markdown 渲染

- 实时预览
- 工具栏快捷操作 (粗体、斜体、标题、链接、图片、代码、列表、表格)
- 服务端渲染 (使用 comrak，支持 GFM)
- 可选允许 HTML
- 复制渲染后的 HTML

### 6. HTTP 请求

类似轻量级 Postman 的 HTTP 请求构建器:

- **HTTP 方法**: GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH
- **Headers**: 自定义请求头，支持启用/禁用
- **Query**: 查询参数，实时预览 Query String
- **Body**:
  - JSON (带格式化按钮)
  - Form Data
  - Text
  - Raw
- **认证**:
  - Basic Auth
  - Bearer Token
  - API Key (Header 或 Query)
- **响应**:
  - 状态码、大小、耗时
  - JSON 自动格式化高亮
  - 响应头查看
- **历史记录**: 自动保存最近 50 条请求
- **模板**: 保存常用请求配置

### 7. 订阅转换

将 URL 订阅转换为 sing-box JSON 配置。页面只保留订阅链接输入、上游订阅参数和模板选择，转换结果会展示配置预览、配置订阅地址、模板信息和节点摘要，并支持下载生成的 JSON 文件。

使用步骤:

1. 打开“订阅转换”。
2. 输入可访问的订阅 URL。
3. 按需调整 `ua`、`emoji`、`eps`，默认分别为 `clashmeta`、`1`、`ssr`。
4. 选择模板，默认使用 `file=1`（`config_template_groups_rule_set_tun`）。
5. 点击“转换”，确认预览和节点列表。
6. 复制生成的配置订阅地址，或点击“下载 JSON”保存当前 sing-box 配置。

模板说明:

- 内置模板来自 `src/tools/sub_convert/templates/`，包括 `sb-config-1.12`、`sb-config-1.14` 等 sing-box 模板。
- 模板中的 `{all}` 会展开为订阅中的全部代理节点；模板内的 `filter` 可按节点名称包含/排除节点。
- 生成的配置地址使用 `file` 参数记录模板，例如 `/api/sub/config/https://example.com/sub?token=abc&ua=clashmeta&emoji=1&eps=ssr&file=1`。
- API 也支持远程模板 URL：请求转换时将 `file` 设为 `https://.../template.json`。远程订阅和远程模板都会拒绝本地、内网和私有 IP 目标。

## API 端点

### 时间转换 `/api/time`

| 端点 | 方法 | 描述 |
|------|------|------|
| `/now` | POST | 获取当前时间 |
| `/timestamp-to-datetime` | POST | 时间戳转日期时间 |
| `/datetime-to-timestamp` | POST | 日期时间转时间戳 |
| `/timezone-convert` | POST | 时区转换 |
| `/format-convert` | POST | 格式转换 |

### JSON 工具 `/api/json`

| 端点 | 方法 | 描述 |
|------|------|------|
| `/format` | POST | 格式化 JSON |
| `/validate` | POST | 校验 JSON |
| `/minify` | POST | 压缩 JSON |
| `/compare` | POST | 比较两个 JSON |
| `/py-dict` | POST | Python Dict 转 JSON |

### 翻译 `/api/translate`

| 端点 | 方法 | 描述 |
|------|------|------|
| `/translate` | POST | 翻译文本 |

### Markdown `/api/markdown`

| 端点 | 方法 | 描述 |
|------|------|------|
| `/render` | POST | 渲染 Markdown |

### HTTP 客户端 `/api/http`

| 端点 | 方法 | 描述 |
|------|------|------|
| `/send` | POST | 发送 HTTP 请求 |

### 订阅转换 `/api/sub`

| 端点 | 方法 | 描述 |
|------|------|------|
| `/templates` | GET | 获取可选 sing-box 模板列表 |
| `/convert` | POST | 根据订阅 URL 和模板生成 sing-box 配置预览 |
| `/config/{*source}` | GET | 返回可直接订阅的 sing-box JSON 配置 |

`POST /api/sub/convert` 请求示例:

```json
{
  "subscription_url": "https://example.com/sub?token=abc",
  "template": "1",
  "file": "1",
  "ua": "clashmeta",
  "emoji": "1",
  "eps": "ssr"
}
```

`template`/`file` 可使用内置模板序号（1-5）、内置模板标识或远程模板 URL。页面默认使用数字序号，例如 `file=1` 对应 `config_template_groups_rule_set_tun`。`ua` 可在 `clashmeta`、`v2rayng`、`sing-box` 中选择；`emoji` 可选择 `1` 或 `0`；`eps` 可填写，留空时默认使用 `ssr`。服务端会在日志中记录转换请求体、实际请求上游的订阅链接和生成的配置订阅链接，便于排查订阅参数问题。

## 技术栈

- **后端**: Rust, Axum, Tokio
- **前端**: HTML, Tailwind CSS (CDN), Vanilla JS
- **依赖库**:
  - `axum` - Web 框架
  - `tokio` - 异步运行时
  - `serde` / `serde_json` - 序列化
  - `chrono` / `chrono-tz` - 时间处理
  - `comrak` - Markdown 渲染
  - `reqwest` - HTTP 客户端
  - `tracing` - 日志

## 项目结构

```
dev-tools/
├── src/
│   ├── main.rs              # 入口文件，路由注册
│   ├── tools.rs             # 模块导出
│   └── tools/
│       ├── time_convert.rs  # 时间转换模块
│       ├── json_tools.rs    # JSON 工具模块
│       ├── translate.rs     # 翻译模块
│       ├── markdown.rs      # Markdown 渲染模块
│       ├── http_client.rs   # HTTP 客户端模块
│       └── sub_convert/     # sing-box 订阅转换模块
├── static/
│   └── index.html           # 前端页面
├── Cargo.toml
└── README.md
```

## 测试

项目包含完整的单元测试:

```bash
# 运行所有测试
cargo test

# 运行特定模块测试
cargo test tools::http_client
```

当前测试覆盖: **163 个测试用例**

## 开发

```bash
# 开发模式运行 (带热重载需配合 cargo-watch)
cargo run

# 检查代码
cargo clippy

# 格式化
cargo fmt
```

## License

MIT License