# 独立服务监督

`wros-deployer service` 生成 systemd 服务文件，不安装或启动宿主服务。`authorize` 先完成验签和逐项人工审核，将一次首次启动授权保存到独立的私有状态目录。服务随后执行 `resume`，在创建 VM 前持久消耗这次授权。首次启动授权不会自动授予崩溃重启权。

需要 Linux cgroup v2。生成的服务使用 `DelegateSubgroup=manager`，要求 systemd 254 或更高版本。目前已在 QEMU 的 x86_64 Linux 来宾中运行真实 systemd 257。五个 Linux 用户态 ABI 的测试不能代替每个平台的内核与服务监督测试。

## 资源与生命周期边界

```text
/sys/fs/cgroup/system.slice/wros-cell.service
  manager                       部署器、验签进程、审计线程
  workloads
    wros-cell
      vm-body                   一个 VM 及其全部后代
  .control                      独立服务监督者保留
```

部署器启动时检查自己确实位于指定根下的 `manager`。根必须属于 root、没有直接进程、提供所需控制器，并设置有限的内存和任务数上限。外部组、未知子组、不足的预算或不一致的旧工作组配置都会阻止启动。部署器只配置这个已委托根内的子组，不自行迁移到其他组，不修改祖先，也不向 VM 交付 cgroup 控制句柄。

XML 必须单独声明管理进程预算：

```xml
<deployment id="cell">
  <supervisor memory-bytes="536870912" pids="128" cpu-micros="100000"
              cpus="0" memory-nodes="0"/>
  <vm id="body" module="body.wasm" sha256="替换为64位小写十六进制摘要"
      policy="body.policy" vm-policy="body-vm.policy"
      uid="10001" gid="10001" memory-bytes="268435456" pids="16"
      cpu-micros="100000" cpus="1" memory-nodes="0"
      start-on-boot="false" restart-on-crash="false"
      restart-limit="3" restart-delay-ms="1000"/>
</deployment>
```

管理组内存最小为 16 MiB，任务数范围为 8～65536，CPU 配额为每 100000 微秒周期允许 1000～100000000 微秒。它们是输入校验边界，不是推荐容量。实际必须为验签工具、模块快照、运行时元数据和日志提供足够资源。CPU 和 NUMA 集合可省略；显式指定时必须完整可用。

整个服务的内存上限为所有 VM 上限、管理组上限和额外 4 MiB 控制余量之和；任务数另加 4 个控制任务。所有组禁用 swap。管理组和每个 VM 分别处理组内 OOM，工作组不能耗尽管理组的子组预算。祖先组压力、调度、热插拔和不可中断内核任务仍可能阻止进展；这些限额不代表物理核心预留、硬实时保证或硬件急停。

`KillMode=mixed` 先向部署器发送 SIGTERM，使其持久保存停机意图；五秒后 systemd 可以终止整个剩余进程树。部署器异常死亡或 panic 可由外层服务重启；明确报告的配置、准入或监督错误返回退出码 1，不进行自动重试。外层另限制六十秒内最多三次启动。这些设置不会增加已经持久批准的 VM 重启次数。

## 审核、生成与启动

按[主指南](README.md)安装受保护的部署器、VM、验签工具和独立信任策略。状态目录必须预先建立，属于 root，权限为 0700。首次审核时，未来的服务 cgroup 可以尚不存在。

```sh
/opt/wros/bin/wros-deployer authorize /protected/bundles/cell/deployment.xml \
  --policy-root /protected/policies \
  --cosign /opt/wros/bin/cosign --scratch-directory /protected/staging \
  --runtime /opt/wros/bin/uwvm2-ros \
  --state-directory /protected/state/cell \
  --supervisor-cgroup /sys/fs/cgroup/system.slice/wros-cell.service
```

默认必须通过终端逐项审核。显式使用 `--accept-recommendations` 才能直接采纳推荐，并产生警告。无签名和错误签名例外仍分别绑定一个 VM 与准确摘要。状态已被其他部署器持有，或服务根还有进程时，`authorize` 拒绝改写授权，不会为替换配置而停止旧部署。

审核完成后，以相同路径生成服务文件：

```sh
/opt/wros/bin/wros-deployer service /protected/bundles/cell/deployment.xml \
  --policy-root /protected/policies \
  --cosign /opt/wros/bin/cosign --scratch-directory /protected/staging \
  --runtime /opt/wros/bin/uwvm2-ros \
  --state-directory /protected/state/cell \
  --supervisor-cgroup /sys/fs/cgroup/system.slice/wros-cell.service \
  > wros-cell.service
```

管理员审阅后安装为 `wros-cell.service`，重新加载 systemd 并启动。开机启用这个服务并不等于授予 VM 开机启动权，仍由审核过的 `start-on-boot` 决定。服务使用完整 CLI 选项、不经 shell；空格、美元符号和百分号按 systemd 的规则处理。配置、可执行文件、信任策略、状态位置或 cgroup 路径变化会使旧授权失效。

首次授权只能在当前内核启动周期内消费一次，不消耗崩溃重试次数；消费后即使管理进程在 VM 创建前崩溃，也不能无限重复首次授权。正常人工停机持久保存停止意图。如果强制终止发生在存储确认前，旧记录可能仍表示调用中断；外层服务监督者必须保持停止，等待操作员处理这种不确定性。已明确批准的开机授权允许在下一次整机启动后冷启动，即使前一启动周期曾人工停机。两种启动都不会恢复运行内存、执行器状态或运动权限。

`--supervisor-cgroup` 与 `--cgroup-parent` 互斥。后者保留用于外部监督下的工作组，不会应用管理进程预算。声明了 supervisor XML 却不使用对应管理模式会报错。

## 缺少 systemd 的平台

生产接口 `--supervisor-cgroup` 不依赖 systemd 库。替代监督者必须创建并独占有界根，将部署器单独放入 `manager`，负责全部后代的生死、限制重试、保证整树停机，并以准确参数执行审核后的 `resume`。部署器检查内核可观察的条件，但无法证明任意外部监督者自身崩溃后一定恢复。

QEMU 中有脚本模拟替代监督者的测试；它不是工业级服务管理器。缺少必要内核控制或独立监督能力的平台默认拒绝，不自动降为弱隔离。特定平台仍需分别完成其监督者、内核、崩溃和关机验收。

## 验证范围

`tests/qemu_service.py` 在真实 systemd 中运行部署器、实际 VM 和故意制造故障的原生测试进程。覆盖无授权拒绝、参数转义、管理组和工作组的 CPU/NUMA/内存/任务限制、错误组身份、首次授权、SIGKILL、拒绝退出的后代、重启预算、人工停机、外层预算不足、未知子组、管理组 OOM 和替代监督者布局。来宾没有网络、宿主共享目录或物理设备，宿主 QEMU 仍处于现有 64 GiB 测试组。

严格 MVP 恢复守护程序、原厂驱动编排、在线更新和完整设备安全监督尚未完成。再次运动仍必须同时满足独立安全状态确认和人工确认。上述测试不构成工业安全认证。
