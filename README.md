# Runtime Java Normalizer

一个面向 agent 本地调用的轻量 Java 组件归一化 helper。

当前默认协议为 `stdin -> stdout`，同时保留 `-input` 文件方式兼容调试。

## 能力
- 读取顶层 JAR 的 `pom.properties`
- 读取 `MANIFEST.MF`
- 展开一层 fat jar / nested jar
- 输出标准化字段：`group_id`、`artifact_id`、`version_`、`purl`、`sha1`
- agent 当前通过 `stdin -> stdout` 管道调用 helper

## 构建
```bash
make build
```

也可以直接指定输出路径：

```bash
make build OUTPUT=/tmp/wazuh-runtime-java-normalizer
```

## 调试调用
```bash
cat > request.json <<'JSON'
{
  "schema_version": "1.0",
  "candidates": [
    {
      "runtime_path": "../wazuh/src/wazuh_modules/syscollector/tests/sysCollectorImp/data/demo-app-1.0.0.jar",
      "discovery_source": "jar",
      "is_direct_runtime_target": true
    }
  ]
}
JSON

cat request.json | ./wazuh-runtime-java-normalizer
# 或兼容旧方式
./wazuh-runtime-java-normalizer -input request.json
```

## 与 agent 对接
- agent 优先按环境变量 `WAZUH_RUNTIME_JAVA_NORMALIZER_PATH` 定位 helper
- 若未设置，则优先尝试 `${WAZUH_HOME}/bin/wazuh-runtime-java-normalizer`
- 若 `WAZUH_HOME` 未设置，则尝试固定安装路径 `/var/ossec/bin/wazuh-runtime-java-normalizer`
- 最后才从 `PATH` 中查找 `wazuh-runtime-java-normalizer`
- helper 不可用时，agent 回退到当前内置归一化逻辑
- 当前主 agent 已使用 `stdin/stdout` 管道调用 helper，不再依赖临时 JSON 文件

## 打包约定
- Linux agent 包默认将 helper 安装到 `/var/ossec/bin/wazuh-runtime-java-normalizer`
- 若使用当前多仓工作区打包 `wazuh-agent`，打包脚本会尝试自动构建并打入该 helper
