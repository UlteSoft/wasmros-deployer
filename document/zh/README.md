# 本地部署与监管

使用 `cargo build --release --locked --offline` 构建。发布配置启用三级优化、完整调试符号和溢出检查。Rust 依赖源码和许可证在 `third-parties/cargo`。

`wros-deployer plan deployment.xml --policy-root /protected/policies` 检查本地文件、Wasm 和驱动摘要、进程预算与权限，并输出验签器和 VM 的完整拟用参数。`wros-deployer review deployment.xml --policy-root /protected/policies` 逐个进程审核接口，可以输入 `allow NAME`、`deny NAME`、`remove NAME` 后 `confirm`。缺省推荐为空。显式使用 `--accept-recommendations` 会显示警告。这两个命令执行预检；`run` 进一步执行不可变映像准入和 VM 进程监管。原生提供方的部署、在线更新、独立看门狗和物理安全接入尚未完成。

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

## 校验已签名的提交

XML 中的策略名在操作员通过命令行指定的独立策略目录内解析。验签程序和信任库置于提交包之外。部署器逐级打开目录并拒绝符号链接。暂存目录须由当前操作员持有，权限为 0700。

```sh
wros-deployer verify deployment.xml --policy-root /protected/policies \
  --cosign /opt/wros/bin/cosign --scratch-directory /protected/staging
```

部署器复制每个模块至私有快照，上限为 256 MiB，核对所复制字节的摘要，然后对该快照执行指定的 wasm-cosign。单次验签限时 30 秒，部署器检查退出状态，并在返回时清理快照。默认要求签名和摘要均有效。生成的执行参数保留 VM 的独立验签步骤。`verify` 在客户程序执行前结束。

对本地开发镜像，`verify` 可分别指定 `--allow-unsigned ID=SHA256` 或 `--allow-invalid-signature ID=SHA256`。选项绑定单个 VM 和上传文件的完整摘要。只有验签器返回与选项相符的拒绝原因时才会放行，显示警告，并在该镜像的拟用参数中省略 VM 二次验签。有效签名仍经过两次检查。缺少信任材料、策略或吊销检查错误、未识别的验签器错误和上传摘要变化均会拒绝。

## 运行已审核的 VM

`run` 要求部署监管进程具有 root 身份，并使用外部服务管理器预先交付的 cgroup v2 子树。各 VM 使用互不相同的非 root 用户和组；这些身份必须由操作员在所有部署中独占预留，当前版本不会自动分配或跨部署锁定身份。验签器和 VM 可执行文件必须位于提交包之外的受保护路径。当前 `run` 遇到原生驱动声明会在启动任何进程之前拒绝。

```xml
<deployment id="cell">
  <vm id="body" module="body.wasm" sha256="替换为64个小写十六进制字符"
      policy="body.policy" vm-policy="body-vm.policy"
      recommendations="body-permissions.xml"
      uid="10001" gid="10001" memory-bytes="268435456" pids="16"
      cpu-micros="100000" restart-on-crash="false"
      restart-limit="3" restart-delay-ms="1000" start-on-boot="false"/>
</deployment>
```

```sh
wros-deployer run deployment.xml --policy-root /protected/policies \
  --cosign /opt/wros/bin/cosign --scratch-directory /protected/staging \
  --runtime /opt/wros/bin/uwvm2-ros \
  --cgroup-parent /sys/fs/cgroup/wros.service/workloads
```

父 cgroup 必须是无直属进程的 domain，由 root 持有且禁止组及其他用户写入；`memory.max` 必须有限，`memory.swap.max` 必须为零，`cgroup.subtree_control` 已启用 `cpu`、`memory`、`pids`。部署器只创建自己独占的 `wros-部署名/vm-实例名` 子组，不修改祖先组。已有部署目录会被拒绝，包括监管进程崩溃后尚未清理的目录。各 VM 的内存预算总和不得超出父组上限。部署器和最终监督者须使用另外受限的组，并预留各自的映像、验签缓冲和日志内存。内核缺少 `cgroup.kill`、pidfd、`close_range`、memfd 封存或所需 namespace 时，启动失败，不降低隔离要求。

子进程先进入对应 cgroup，再创建 network、IPC、UTS、mount、cgroup namespace，清空附加组，设置非 root 的真实、有效和保存 UID/GID，并启用 `no_new_privs`。部署器从封存的准入映像复制字节到私有 tmpfs 的 `/tmp/wros-admitted.wasm`，在执行 VM 前将文件系统设为只读。tmpfs 上限为 257 MiB，实际分配计入子进程的 cgroup。VM 原有的拒绝符号链接规则继续生效。日志管道归最终 VM 用户所有，使日志库在降权后能重新打开自身管道。其他非指定描述符在执行时关闭。这提供资源和部分操作系统隔离，不等于完整的文件系统或系统调用沙盒。

正常签名部署需要两个反回滚状态库。用官方 wasm-cosign 初始化器分别初始化特权准入的 `policy` 和 VM 用户的 `vm-policy`；两份策略的信任根、签名者、算法、版本和限制必须完全一致，只允许 `state_dir` 不同。VM 状态目录及其中初始化文件属于 VM 用户，目录权限 0700、文件权限 0600；策略文件仍归管理员持有，并允许 VM 读取。不能修改策略路径后直接复制旧的反回滚记录，因为记录绑定策略指纹。VM 自己完成第二次校验。

`run` 接受与 `verify` 相同的逐映像签名例外，显示独立警告。`--accept-recommendations` 只跳过本次交互审核，不放宽签名要求。命令复述配置和完整 VM 参数，但不注册开机服务；XML 中的开机意图还需要后续服务管理集成。

## CPU 与 NUMA 放置

每个 `vm` 可以单独指定 `cpus="2-3,8"` 和 `memory-nodes="1"`，两个属性均可省略。省略时继承委托父组的允许集合；空字符串无效。列表使用升序十进制编号及不重叠区间，禁止空白、正负号和前导零。每个列表最多 4096 字节，编号必须小于 8192。相邻区间会先合并，再进行比较和配置复述。

显式放置要求父组的 `cgroup.subtree_control` 已启用 `cpuset`。部署器在创建工作负载前，将所有请求集合与父组的 `cpuset.cpus.effective`、`cpuset.mems.effective` 比较；不存在、离线或未委托的资源都会被拒绝。随后设置子组的内存节点和 CPU，并验证实际生效集合。每次冷重启都重新验证，在执行 VM 前设置 CPU 亲和性。来宾不能通过修改自身亲和性或内存策略来扩大 cgroup 允许范围。部署器不修改祖先组的控制器或资源集合。

这些设置限制可运行和分配内存的位置，不代表独占核心、实时调度、已有共享页的节点归属或延时保证。CPU 热插拔和管理员操作仍可能改变启动后的实际集合。即使亲和性包含多个核心，CPU 配额也可能导致节流，必须在控制期限测试中考虑。并行通信对照应区分物理核心和 SMT 线程，相邻 CPU 编号可能属于同一物理核。需要隔离中断或预留监管资源时，由平台服务管理器完成配置。

## 故障和人工停机

退出码为零时该实例结束。只有 `restart-on-crash="true"` 才允许冷重启，次数不得超过 `restart-limit`，两次启动间隔不得小于 `restart-delay-ms`。默认上限为三次、间隔一秒，但默认没有重启授权。次数可设 0 至 32，间隔可设 100 至 60000 毫秒。每次启动使用新的代次、相同的封存映像且没有运动权限。旧 cgroup 的所有后代退出后才允许新代次启动。CPU 配额固定以 100000 微秒为周期，`cpu-micros` 默认 100000；这是会明确报告的资源限制。

SIGINT、SIGTERM 或 SIGHUP 会停止恢复，通过 pidfd 请求退出，最多等待两秒，再终止残留的整个后代 cgroup。诊断输出每代最多记录 8 KiB，读取工作量也有上限；退出状态和内存、任务数限额事件会被报告。控制循环每五毫秒轮询，不承担物理急停。内核不可中断任务仍可能需要最终监督者处理。部署器死亡会触发直属 VM 的父进程死亡信号；systemd 或等价的平台监督者还必须负责回收整棵后代树。持久化停机意图、开机恢复和监督者自身恢复尚未实现。

运行期审计使用独立写入线程和有界队列，最多 32 条记录，每条最多 32 KiB。进程监管循环不会等待日志接收端。队列饱和或写入错误会停止部署；VM 停机后最多等待 500 毫秒排空日志，未能排空时以失败状态退出。这避免已满管道或卡住的日志收集器阻塞人工停机。预检输出发生在任何客户程序启动之前。

## 临时内核测试

`tests/qemu_supervisor.py` 创建仅使用内存的全新 Linux 来宾，不挂载宿主磁盘、共享目录、实体设备或网络。测试必须经过现有 64 GiB、零 swap 的 cgroup；来宾内存上限为 4 GiB，使用两个模拟 CPU。参数指定官方内核及固件、构建后的部署器和 VM、发布版 wasm-cosign，以及新生成的 `tests/wsea_preflight.py` 签名夹具。输入摘要和结果写入指定的 `.tmp` 目录。原生故障程序只是测试替身，真实 VM 用例在结果中单独标明。该测试不代表五个 Linux ABI、原厂硬件、systemd 恢复或工业安全认证已经通过。

`--sdk-module` 接收实际由 SDK 编译、调用 `uwvm_ros_v2.abi` 的程序。测试分别允许和拒绝该接口，验证 SDK 产物经过部署器和 VM 后的授权行为。`tests/linux_abi.py` 另行交叉编译 Rust 实现，并在 x86_64、i686、AArch64、ARM 硬浮点和 ARM 软浮点运行契约测试；用户态 ABI 检查不能替代各架构的特权内核测试。

来宾配置两个 NUMA 节点，每个节点一个虚拟 CPU、2 GiB 内存。放置测试检查实际亲和性、已写入页面所在节点、扩大 CPU／内存策略被拒绝、崩溃重启后的约束、不可用资源、收窄的父组和缺失的控制器；两个真实 VM 也分别绑定不同 CPU／节点。当前内核测试共 20 项，用户态契约测试每个 ABI 运行 12 项，结果记录绑定源码、构建配置与程序摘要。仿真结果不用于宣称 NUMA 性能或硬实时保证。
