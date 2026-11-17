# 本地部署预检

使用 `cargo build --release --locked --offline` 构建。Rust 依赖源码在 `third-parties/cargo`。

`wros-deployer plan deployment.xml` 检查本地文件、Wasm 和驱动摘要、进程预算与权限，并输出验签器和 VM 的完整拟用参数。`wros-deployer review deployment.xml` 逐个进程审核接口，可以输入 `allow NAME`、`deny NAME`、`remove NAME` 后 `confirm`。缺省推荐为空。显式使用 `--accept-recommendations` 会显示警告。这两个命令执行预检；生产进程监管、隔离启动、在线更新和物理安全接收端仍待实现与验证。

```xml
<deployment id="cell">
  <vm id="body" module="body.wasm" sha256="替换为64个小写十六进制字符"
      policy="body.policy" recommendations="body-permissions.xml"
      memory-bytes="268435456" pids="8" start-on-boot="false" restart-on-crash="false"/>
</deployment>
```

推荐权限放在单独的 XML，例如 `<recommendations><interface name="abi" expose="allow"/></recommendations>`。接口暴露与设备资源授权分别审核。当前预检处理接口暴露。

厂商 URL 由上层拉取器解析，部署器接收本地文件、版本及摘要。每个可选驱动条目显式指定本地文件、格式、版本、摘要及物理设备身份。缺包、摘要不匹配、同一清单重复声明设备所有者均拒绝。实体机器的跨进程唯一控制权还需要受信设备代理。

部署设计要求正常签名通过 wasm-cosign 与 VM 两次校验。放宽无签和放宽错误签名分别由操作员确认并提示。上电和恢复仅可冷启动；运动必须收到独立安全确认和人工授权。Linux 默认由 systemd 最终监管，其他平台的监督者须提供等价的停机语义、资源所有权和恢复机制。恢复接口待故障测试后才冻结。
