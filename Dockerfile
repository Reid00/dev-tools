# 构建阶段
FROM rust:1.90-alpine AS builder

# 安装构建依赖
RUN apk add --no-cache musl-dev

WORKDIR /app

# 复制 Cargo 文件并缓存依赖
COPY Cargo.toml ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && cargo build --release && rm -rf src

# 复制源代码并构建
COPY src ./src
COPY static ./static
RUN touch src/main.rs && cargo build --release

# 运行阶段
FROM alpine:3.19

# 安装运行时依赖
RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

# 从构建阶段复制二进制文件
COPY --from=builder /app/target/release/dev-tools /app/dev-tools

# 暴露端口
EXPOSE 3000

# 设置环境变量
ENV RUST_LOG=info
ENV TZ=Asia/Shanghai

# 启动应用
CMD ["./dev-tools"]