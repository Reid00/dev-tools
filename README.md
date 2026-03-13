# Dev Tools - 开发者工具箱

一个基于 Rust + Axum 构建的轻量级开发者工具箱，提供常用的开发工具，通过 Web UI 进行交互。

## 功能概览

| 工具 | 描述 |
|------|------|
| 🕐 时间转换 | 时间戳与日期时间互转、时区转换、格式转换 |
| 📄 JSON 格式化 | JSON 格式化、压缩、校验、键排序 |
| 🐍 Dict 转 JSON | Python Dict 字符串转 JSON (支持 True/False/None、单引号、元组等) |
| 🌐 翻译工具 | 中英文互译 (基于 MyMemory API) |
| ✍️ Markdown 渲染 | Markdown 实时预览、服务端渲染、工具栏快捷操作 |
| 🔌 HTTP 请求 | HTTP 请求构建器 (类似轻量级 Postman) |

## 快速开始

### 环境要求

- Rust 1.75+ (edition 2024)
- Cargo

### 安装运行

```bash
# 克隆项目
git clone https://github.com/yourname/dev-tools.git
cd dev-tools

# 运行开发服务器
cargo run

# 或构建发布版本
cargo build --release
./target/release/dev-tools
```

服务启动后访问: **http://localhost:3000**

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
│       └── http_client.rs   # HTTP 客户端模块
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

当前测试覆盖: **159 个测试用例**

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