# 从一个 XML 入口部署

将入口 XML 传给 `wros-deployer plan`、`review`、`verify`、`authorize`、`service` 或 `run`。部署配置和推荐权限分别使用独立的 XML。包内路径统一相对于入口文件所在目录，片段中的路径也遵循同一规则。

以一个遥测进程为例，入口文件可以引用遥测包中的进程声明。

```xml
<deployment id="cell">
  <include file="telemetry/process.xml"/>
</deployment>
```

在 `telemetry/process.xml` 中声明 Wasm、摘要、两份受保护的信任策略和推荐权限文件。部署时将示例摘要替换为已签名文件的 SHA-256。信任策略路径相对于操作员指定的策略根目录。

```xml
<deployment-fragment>
  <vm id="telemetry" module="telemetry/reader.wasm"
      sha256="0000000000000000000000000000000000000000000000000000000000000000"
      policy="telemetry-admission.policy" vm-policy="telemetry-runtime.policy"
      recommendations="telemetry/rights.xml" uid="10021" gid="10021"
      memory-bytes="134217728" pids="8"/>
</deployment-fragment>
```

部署片段可以继续引用其他片段，也可以声明 VM 和驱动。监督者配置由入口文件统一声明。部署器在整个依赖图内核对进程 ID、驱动归属和资源冲突。每个 VM 单独审核权限。例如，`telemetry/rights.xml` 可以复用公用时钟配置。

```xml
<recommendations>
  <include file="common/clocks.xml"/>
  <interface name="type.describe" expose="allow"/>
</recommendations>
```

被引用的权限文件也以 `recommendations` 为根元素。审查界面列出源文件、摘要、待运行文件和有效权限。同一文件被多条路径引用时，在每个依赖图内只展开一次。不同声明中的重复权限、循环引用、符号链接、绝对路径和缺失文件会导致预检失败。一次审查最多读取 256 个 XML 文件，合计上限 8 MiB。单个图的深度上限为 16，展开后的大小上限为 256 KiB。

运行部署时，部署器在第一个权限提示前检查全部 Wasm 和 ELF。消费批准记录前会复核本次审阅的 XML。持久化恢复绑定部署配置的依赖图，并使用每个 VM 此前确认的权限。变更工作负载声明后需要重新批准。

## 同一 VM 内的 Wasm 库

一个 VM 最多注册 32 个库。主模块和每个库均需声明 WSEA 签名中的 `module-id`。库的 `namespace` 是调用方 Wasm 指令实际导入的模块名。每个调用方通过 `requires` 列出自己的直接依赖。模块路径相对于部署包根目录，示例中的摘要需替换为各个完整已签名文件的 SHA-256。

```xml
<deployment id="cell">
  <vm id="telemetry" module-id="example.telemetry" module="telemetry.wasm"
      sha256="0000000000000000000000000000000000000000000000000000000000000000"
      policy="admission.policy" vm-policy="runtime.policy"
      uid="10021" gid="10021" memory-bytes="134217728" pids="8">
    <requires module="units"/>
    <library namespace="units" module-id="example.units" module="lib/units.wasm"
        sha256="1111111111111111111111111111111111111111111111111111111111111111"
        policy="admission.policy" vm-policy="runtime.policy"/>
  </vm>
</deployment>
```

库可用自己的 `requires` 声明下一级依赖。预检拒绝循环、不可达声明、重复名称及多余或缺失的依赖边，并逐项核对真实导入的模块名、字段、函数签名和提供方导出。支持的链路为参数和返回值仅使用 `i32`、`i64`、`f32`、`f64` 的核心 Wasm 函数。每次启动时，库的宿主权限均为空。库导入宿主函数、使用共享内存，或跨模块传递内存、表、全局变量、标签和引用类型，均会在预检阶段被拒绝。主模块单独使用其已审核的主机接口。

部署器逐件验证签名身份和完整文件摘要，VM 再用受保护的独立回滚存储验证所选模块。WSEA 公用策略可以覆盖多个签名身份，两级策略必须具有相同规则、不同回滚目录。监督者从密封文件复制确切字节，VM 只读取其私有只读镜像。主模块与库的文件总计上限为 256 MiB。预加载只使用部署包中的显式声明，导入名不会触发对系统搜索路径的遍历。

`--allow-unsigned telemetry/units=SHA256` 和 `--allow-invalid-signature telemetry/units=SHA256` 只针对指定 VM、库名、完整摘要及对应的拒绝类型。持其他有效签名身份的文件仍会被拒绝。例外保留原依赖检查和零宿主权限。监督者持久化恢复时会按已绑定的配置、镜像摘要、信任文件及批准记录重新读取并验证完整依赖图。运行中的监督者重新启动 VM 时，继续使用同一组已密封文件，并再次执行 VM 签名验证。
