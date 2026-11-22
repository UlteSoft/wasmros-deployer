# 本地部署与监管

使用 `cargo build --release --locked --offline` 构建。发布配置启用三级优化、完整调试符号和溢出检查。Rust 依赖源码和许可证在 `third-parties/cargo`。

[本机加密通道交付约定](attachment-provisioning.md)说明了 Rust 密钥和描述符交付组件及其真实 VM 测试。
正式 CLI 用这些组件启动经审核的只读原生提供方。

每个部署的 VM 必须启用[内核设备访问控制](device-isolation.md)。该模块同时提供
确切设备规则和原部署器归属登记；native 驱动生命周期仍需独立联动。

`wros-deployer plan deployment.xml --policy-root /protected/policies` 检查本地文件、Wasm 和驱动摘要、进程预算与权限，并输出验签器和 VM 的完整拟用参数。`wros-deployer review deployment.xml --policy-root /protected/policies` 逐个进程审核接口，可以输入 `allow NAME`、`deny NAME`、`remove NAME` 或 `hide permission.report` 后 `confirm`。缺省推荐不授予权限。输入 `show` 可重新查看评分，输入 `cancel` 可退出。使用 `--accept-recommendations` 会直接采纳已读取的建议并显示警告，仍会展示生效权限和按选项生成的风险报告。这两个命令执行预检；`run` 进一步执行不可变映像准入和 VM 进程监管。原生提供方的自动恢复、在线更新、独立看门狗和物理安全接入尚未完成。

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

XML 中的策略名在操作员通过命令行指定的独立策略目录内解析。验签程序和信任库置于提交包之外。部署 XML 和制品均从同一个固定的包目录读取。制品查找拒绝路径中的符号链接，并在打开内容前检查最终 inode 的类型，只读取普通文件。暂存目录须由当前操作员持有，权限为 0700。

```sh
wros-deployer verify deployment.xml --policy-root /protected/policies \
  --cosign /opt/wros/bin/cosign --scratch-directory /protected/staging
```

部署器复制每个模块至私有快照，上限为 256 MiB，核对所复制字节的摘要，然后对该快照执行指定的 wasm-cosign。单次验签限时 30 秒，部署器检查退出状态，并在返回时清理快照。默认要求签名和摘要均有效。生成的执行参数保留 VM 的独立验签步骤。`verify` 在客户程序执行前结束。

对本地开发镜像，`verify` 可分别指定 `--allow-unsigned ID=SHA256` 或 `--allow-invalid-signature ID=SHA256`。选项绑定单个 VM 和上传文件的完整摘要。只有验签器返回与选项相符的拒绝原因时才会放行，显示警告，并在该镜像的拟用参数中省略 VM 二次验签。有效签名仍经过两次检查。缺少信任材料、策略或吊销检查错误、未识别的验签器错误和上传摘要变化均会拒绝。

CLI 会逐项显示每个 ROSv2 接口的审核结果（允许或拒绝），并明确提示权限列表为空的情形。开放接口与授予指定资源的操作权限分别管理。

### 校验原生 ELF 驱动

清单包含 `<driver>` 时，给 `verify` 加上 `--elf-verifier /opt/wros/bin/uwvm2-ros`。`elf-signer` 指定管理员 `--policy-root` 下的 PEM X.509 证书。部署器核对整个签名 ELF 的 SHA-256，再对私有快照执行 `uwvm2-ros --verify-elf-driver KIND ELF SIGNER.pem`。该命令检查 Linux 追加式 CMS、固定签名者、证书有效期、摘要强度和 ELF 的宿主 ABI，预检阶段不会加载驱动。

厂商可用同一把 P-384 私钥和证书发布两种制品。Wasm 使用 `cosign wasm secure sign --algorithm ES384`，同时提供其 WSEA 策略和 CRL。ELF 签名后，将整个签名文件的摘要填入部署 XML。

```sh
scripts/sign-file sha384 publisher.key publisher.pem driver.so driver.signed.so
sha256sum driver.signed.so
```

默认拒绝无签名和签名错误的 ELF。`verify` 和显式 `run` 分别用 `--allow-unsigned-elf DRIVER=SHA256` 和 `--allow-invalid-elf-signature DRIVER=SHA256` 放行匹配驱动 ID、完整摘要和拒绝原因的制品，并显示警告。即使文件内容相同，每个驱动 ID 也须单独放行。Wasm 同样按 VM ID 分别放行。损坏的封装、信任错误和未知验签失败仍会拒绝。管理员须从固定的 ELF 信任库移除已吊销或失陷的证书。

### 启动只读原生提供方

在可执行类型的 `<driver kind="executable" ...>` 下声明与 VM 的连接。

```xml
<attachment vm="body" alias="joints" sandbox="go2" uid="24002" gid="24002"
    contract-sha256="替换为64个小写十六进制字符"
    memory-bytes="268435456" pids="32" cpu-micros="100000"/>
```

`run` 增加 `--driver-root /protected/provider-roots` 和 `--elf-verifier /opt/wros/bin/uwvm2-ros`。管理员在 `/protected/provider-roots/go2` 准备已审核的动态加载器、依赖与配置，全部归 root 所有且禁止组和其他用户写入。另需留出空的 `proc` 目录，用于挂载带 `hidepid=2,subset=pid` 的只读进程视图。原厂库可读取自身可执行文件名和时钟命名空间身份。其余目录以只读方式挂载，网络仅有独立回环，实体设备授权为空。原厂共享库通过同一隔离目录中的签名 ELF 适配器接入。

每个 VM 当前可连接一个独立 UID、GID 和 cgroup 的提供方。单独审核 `capability.open`、`driver.connect`、`driver.submit`、`driver.result`、`driver.disconnect` 及资源权限 `driver/joints/buffer.read`。推荐权限可用 `<driver-resource alias="joints" operation="buffer.read" access="allow"/>` 表达。驱动进程通过继承描述符完成身份交付，之后用认证 TLS 处理有界的 `buffer.read`。

部署器先核对完整 ELF 摘要并密封映像，预检和启动前分别验签，随后用 `execveat` 执行同一 inode。两次验签结果须一致。签名者在启动前被撤下或发生变化时，启动会失败。原生驱动目前要求操作员显式运行，自动启动、自动重启和服务模式仍用于纯 VM 部署。

## 运行已审核的 VM

`run` 要求部署监管进程具有 root 身份，并使用外部服务管理器预先交付的 cgroup v2 子树。各 VM 和原生提供方使用互不相同的非 root 用户和组。操作员为 WROS 预留专用系统身份，部署器通过[宿主身份所有权登记](host-identities.md)拒绝共享登记目录的管理进程之间发生身份冲突。验签器和 VM 可执行文件必须位于提交包之外的受保护路径。

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

父 cgroup 必须是无直属进程的 domain，由 root 持有且禁止组及其他用户写入；`memory.max` 必须有限，`memory.swap.max` 必须为零，`cgroup.subtree_control` 已启用 `cpu`、`memory`、`pids`。部署器只创建自己独占的 `wros-部署名/vm-实例名` 子组，不修改祖先组。未启用持久化状态时，已有部署目录会被拒绝，包括监管进程崩溃后尚未清理的目录。下面的持久化恢复路径持有独占锁，只能回收之前已批准的实例集合。各 VM 的内存预算总和不得超出父组上限。部署器和最终监督者须使用另外受限的组，并预留各自的映像、验签缓冲和日志内存。内核缺少 `cgroup.kill`、pidfd、`close_range`、memfd 封存或所需 namespace 时，启动失败，不降低隔离要求。

子进程先进入对应 cgroup，再创建 network、IPC、UTS、mount、cgroup namespace，清空附加组，设置非 root 的真实、有效和保存 UID/GID，并启用 `no_new_privs`。部署器从封存的准入映像复制字节到私有 tmpfs 的 `/tmp/wros-admitted.wasm`，在执行 VM 前将文件系统设为只读。tmpfs 上限为 257 MiB，实际分配计入子进程的 cgroup。VM 原有的拒绝符号链接规则继续生效。日志管道归最终 VM 用户所有，使日志库在降权后能重新打开自身管道。其他非指定描述符在执行时关闭。这提供资源和部分操作系统隔离，不等于完整的文件系统或系统调用沙盒。

正常签名部署需要两个反回滚状态库。用官方 wasm-cosign 初始化器分别初始化特权准入的 `policy` 和 VM 用户的 `vm-policy`；两份策略的信任根、签名者、算法、版本和限制必须完全一致，只允许 `state_dir` 不同。VM 状态目录及其中初始化文件属于 VM 用户，目录权限 0700、文件权限 0600；策略文件仍归管理员持有，并允许 VM 读取。不能修改策略路径后直接复制旧的反回滚记录，因为记录绑定策略指纹。VM 自己完成第二次校验。

`run` 接受与 `verify` 相同的逐映像签名例外，显示独立警告。审核在终端进行。默认逐项修改并确认每个 VM。`--accept-recommendations` 会一步采纳全部已读取的建议。两种方式均展示生效权限和完整参数，输入 `deploy 部署ID` 才会启动。关闭终端或未确认会停止启动。命令复述配置和完整 VM 参数，但不注册开机服务；XML 中的开机意图还需要后续服务管理集成。

每个受管 VM 显式使用 `--runtime-memtag-mode sync` 和
`--runtime-memtag-action crash`。标签不匹配时，VM 在故障点终止。
编译时关闭 WasmMTE 生成的模块按普通 Wasm 执行，仍执行原有的边界检查。

审核对有明确依据的权限按 0 至 10 分评分。只读时钟为 0 分，有潜在硬件影响的控制项及逐摘要验签例外属于高风险。证据不足的项目显示为 `UNASSESSED`。分数描述授予权限的后果，不授予权限。审核显示重叠的显式 CPU、NUMA 放置及共用的原生驱动沙箱路径，并从与摘要绑定的 Wasm 中列出导入声明。导入名称是链接接口，可能对应宿主服务。当前清单未提供预加载 Wasm 或任意宿主目录挂载授权。

进程内原生库预加载为 10 分，部署器拒绝 `--wasm-register-dl` 及其简写 `-Wdl`。`report/preloaddl` 仅控制已获授权的来宾能否读取 VM 的预加载构建状态。生产 VM 默认不编译原生预加载。独立进程内运行的签名 ELF 驱动按自己的规则准入。

部署器默认展示 5/10 及以上的项目，未评估项目单独列出。可用
`--risk-report 0` 至 `--risk-report 10` 设置最低展示分数，也接受
`--risk-report '>=7'` 的写法。`--risk-report none` 关闭这份报告。
手动逐个审核和一键采纳均使用这一独立设置。生效权限、最终部署确认和必须显示的验签或策略诊断仍按原有规则处理。

来宾默认可通过 `permission.report` 只读查询自己的权限，可按权限族或具体函数限制内容。
`deny permission.report` 保留导入并拒绝调用，`hide permission.report` 隐藏导入。
XML 使用 `<interface name="permission.report" expose="hidden"/>` 建议隐藏。
移除整接口的显式决定会恢复默认只读查询。查询其他模块或 VM 的元数据仍需要各自的接口和目标授权。

已弃用的 `uwvm_ros1_v1.abi_version` 和 `uwvm_ros2_v1.abi_version` 权限分别仅开放对应的版本查询，需要显式编译相应 legacy ABI 的 VM。缺少该 ABI 时，VM 拒绝启动参数。这些权限不提供网关、数据访问或其他 legacy 接口。

## CPU 与 NUMA 放置

每个 `vm` 可以单独指定 `cpus="2-3,8"` 和 `memory-nodes="1"`，两个属性均可省略。省略时继承委托父组的允许集合；空字符串无效。列表使用升序十进制编号及不重叠区间，禁止空白、正负号和前导零。每个列表最多 4096 字节，编号必须小于 8192。相邻区间会先合并，再进行比较和配置复述。

显式放置要求父组的 `cgroup.subtree_control` 已启用 `cpuset`。部署器在创建工作负载前，将所有请求集合与父组的 `cpuset.cpus.effective`、`cpuset.mems.effective` 比较；不存在、离线或未委托的资源都会被拒绝。随后设置子组的内存节点和 CPU，并验证实际生效集合。每次冷重启都重新验证，在执行 VM 前设置 CPU 亲和性。来宾不能通过修改自身亲和性或内存策略来扩大 cgroup 允许范围。部署器不修改祖先组的控制器或资源集合。

这些设置限制可运行和分配内存的位置，不代表独占核心、实时调度、已有共享页的节点归属或延时保证。CPU 热插拔和管理员操作仍可能改变启动后的实际集合。即使亲和性包含多个核心，CPU 配额也可能导致节流，必须在控制期限测试中考虑。并行通信对照应区分物理核心和 SMT 线程，相邻 CPU 编号可能属于同一物理核。需要隔离中断或预留监管资源时，由平台服务管理器完成配置。

## 故障和人工停机

退出码为零时该实例结束。只有 `restart-on-crash="true"` 才允许冷重启，次数不得超过 `restart-limit`，两次启动间隔不得小于 `restart-delay-ms`。默认上限为三次、间隔一秒，但默认没有重启授权。次数可设 0 至 32，间隔可设 100 至 60000 毫秒。每次启动使用新的代次、相同的封存映像且没有运动权限。旧 cgroup 的所有后代退出后才允许新代次启动。CPU 配额固定以 100000 微秒为周期，`cpu-micros` 默认 100000；这是会明确报告的资源限制。

SIGINT、SIGTERM 或 SIGHUP 会停止恢复，通过 pidfd 请求退出，最多等待两秒，再终止残留的整个后代 cgroup。诊断输出每代最多记录 8 KiB，读取工作量也有上限；退出状态和内存、任务数限额事件会被报告。控制循环每五毫秒轮询，不承担物理急停。内核不可中断任务仍可能需要最终监督者处理。部署器死亡会触发直属 VM 的父进程死亡信号；systemd 或等价的平台监督者还必须负责回收整棵后代树。可选的持久化批准记录支持跨监管进程保留停机意图、开机授权和有界冷启动权限；仍须由外部服务管理器调用恢复。自动服务安装和独立看门狗尚未实现。

所有直属 VM 共享两秒退出宽限期。随后部署器向这一部署专用根组的 `cgroup.kill` 写入一次，强制停止该树的所有残留进程。后代退出和直属子进程回收共享两秒等待预算。预算用完后仍有未退出或未回收的进程时，部署器向外层监督者报告失败。内核调度、不可中断任务和持久存储阻塞仍可能影响实际停机时间。 [Linux cgroup v2 文档](https://docs.kernel.org/admin-guide/cgroup-v2.html#core-interface-files)

运行期审计使用独立写入线程和有界队列，最多 32 条记录，每条最多 32 KiB。进程监管循环不会等待日志接收端。队列饱和或写入错误会停止部署；VM 停机后最多等待 500 毫秒排空日志，未能排空时以失败状态退出。这避免已满管道或卡住的日志收集器阻塞人工停机。预检输出发生在任何客户程序启动之前。

管理进程独立限额、整树停机及 `authorize`／`service` 的用法见[独立服务监督](service-supervision.md)。审核保存后不立即启动，独立监督者通过 `resume --supervisor-cgroup` 消费首次授权。自动安装和严格 MVP 看门狗尚未实现。

## 持久化批准与冷启动

在经过人工审核的 `run` 命令中加入 `--state-directory /protected/state/cell`。目录须已存在，位于提交包之外，属于 root，权限为 0700，祖先路径受保护；记录文件必须为 0600 的普通文件且只有一个硬链接。独占锁覆盖准入、执行和清理全过程。每个部署使用独立状态目录和工作负载子树；运行期间禁止复制、编辑或回滚记录。

全部审核和验签通过后，部署器保存实际选定的接口权限和逐摘要签名例外。后续自动启动复用这份批准，不重新应用推荐文件。绑定内容包括 XML 原始字节、清单／状态／cgroup／策略的绝对路径、部署器／VM／验签器的二进制摘要和两份策略文件。更改这些内容后，必须先安全停止原部署，再重新人工审核新部署；这不是热更新接口。

最终服务管理器可以使用相同路径和程序调用：

```sh
wros-deployer resume /protected/bundles/cell/deployment.xml \
  --policy-root /protected/policies \
  --cosign /opt/wros/bin/cosign --scratch-directory /protected/staging \
  --runtime /opt/wros/bin/uwvm2-ros \
  --cgroup-parent /sys/fs/cgroup/wros.service/workloads \
  --state-directory /protected/state/cell
```

`resume` 要求批准记录匹配，不接受 `--accept-recommendations` 或新的签名例外。它重新验签，正常签名仍由 VM 二次验证；先前批准的签名例外会再次警告，上传摘要仍必须一致。它先检查并清空原先批准的 cgroup 树，再选择新工作；未知子组或嵌套子组会在发出终止操作前拒绝恢复。已有进程不会被当成新部署接管，第二个管理进程也不能取得同一状态锁。

同一次内核启动期间，部署器崩溃和 VM 崩溃共用 `restart-limit`。只有中断或故障实例且明确设置 `restart-on-crash="true"` 才能自动重启。正常结束、人工停机或已阻断的部署不会在本次开机内自动恢复。自动冷启动至少等待所选实例中最长的重启间隔，人工停机可取消等待。再次人工审核的 `run` 可以重置次数，但保留递增的代次。

检测到新的内核启动身份后，仅 `start-on-boot="true"` 的实例可以冷启动。本次开机的重试次数重新计数，代次继续递增。按照这个明确的开机授权，机器重启前已人工停止的 VM 也可以在下一次开机启动；不希望这样运行时，应重新审核并关闭开机授权。仅有崩溃重启授权不代表允许开机自启。任何恢复都不还原运行内存、执行器状态或运动权限；运动仍要求独立安全状态确认和人工确认。

记录最多 1 MiB，最多 128 个实例，每个实例最多 256 个登记接口权限。启动新代次前，先写私有临时文件并同步文件，随后原子替换记录并同步目录；人工停机意图先于来宾终止持久化。损坏、截断、不安全文件权限、符号链接、硬链接、写入失败和磁盘满均会拒绝继续。校验和只检测损坏，不是授权签名，也不能防止管理员回滚磁盘。断电残留的 `pending-*` 不会被当成批准记录；管理员可以在停机时清理。

持久化写入只发生在部署生命周期上，不发生在每次 ROS／DDS、模型或驱动消息调用上。磁盘 I/O 可能缓慢或不可中断，因此它不承担物理急停。systemd 或等价独立平台监督者仍需负责管理服务启动、整棵进程树停机和有界重启；当前不自动安装服务，也未实现严格 MVP 恢复看门狗。管理进程需要独立的内存与 CPU 余量。

## 临时内核测试

`tests/qemu_supervisor.py` 创建仅使用内存的全新 Linux 来宾，不挂载宿主磁盘、共享目录、实体设备或网络。测试必须经过现有 64 GiB、零 swap 的 cgroup；来宾内存上限为 4 GiB，使用两个模拟 CPU。参数指定官方内核及固件、构建后的部署器和 VM、发布版 wasm-cosign，以及新生成的 `tests/wsea_preflight.py` 签名夹具。输入摘要和结果写入指定的 `.tmp` 目录。原生故障程序只是测试替身，真实 VM 用例在结果中单独标明。该测试不代表五个 Linux ABI、原厂硬件、systemd 恢复或工业安全认证已经通过。

`--sdk-module` 接收实际由 SDK 编译、调用 `uwvm_ros_v2.abi` 的程序。测试分别允许和拒绝该接口，验证 SDK 产物经过部署器和 VM 后的授权行为。`tests/linux_abi.py` 另行交叉编译 Rust 实现，并在 x86_64、i686、AArch64、ARM 硬浮点和 ARM 软浮点运行契约测试；用户态 ABI 检查不能替代各架构的特权内核测试。

来宾配置两个 NUMA 节点，每个节点一个虚拟 CPU、2 GiB 内存。放置测试检查实际亲和性、已写入页面所在节点、扩大 CPU／内存策略被拒绝、崩溃重启后的约束、不可用资源、收窄的父组和缺失的控制器；两个真实 VM 也分别绑定不同 CPU／节点。内核测试共 37 项，包括跨部署身份冲突和身份独立的并行部署；用户态契约测试每个 ABI 现包含 35 项，包括接入密钥生成、封存记录和描述符注入检查，结果记录绑定源码、构建配置与程序摘要。仿真结果不用于宣称 NUMA 性能或硬实时保证。

`tests/qemu_powerloss.py` 在已完成的内核夹具基础上，于 `.tmp` 新建 64 MiB 的虚拟 ext4 磁盘，使用两个虚拟 CPU 和 2 GiB 内存。输入与内核匹配的 Debian 安装器 kernel-image、ext4 和存储模块包；只将选中的普通模块文件放入来宾，宿主不加载这些内核模块。首次启动两个真实 VM 后直接强杀 QEMU，再进行两次全新内核启动，验证开机授权、递增代次和持久化停机意图。最后写满虚拟磁盘，验证发布状态失败时保留原记录且不启动 VM。结果记录三个不同的内核 boot ID。这覆盖来宾突然消失和文件系统写满，不等于物理存储缓存、硬件停机电路或平台服务管理器恢复已通过验收。

在 4 GiB 的一次性 QEMU 监督测试中，可用 `--sdk-memory-bytes 字节数` 指定 SDK 应用的来宾内存预算，默认为 256 MiB。嵌入语言运行时在模块加载和编译期间可能需要更多内存。结果文件会记录授权和拒绝这两项 SDK 测试的预算。授权用例若被内核因内存不足而终止，测试判为失败。

每个 VM 可通过 XML 属性 `engine="aot"`（默认）或 `engine="interpreter"` 选择执行引擎。审阅界面显示所选引擎，启动记录保留完整 VM 参数。两种引擎遵守相同的导入权限和资源配额。应在目标设备的 cgroup 中实测启动耗时和内存。QEMU 测试通过 `--sdk-engine` 指定同一选项。

使用 AOT 引擎的 VM 可在其 XML 元素上设置 `aot-policy="fast-compile"` 以优先缩短冷启动时间，也可选择 `default`、`balanced` 或 `max`。审阅时显示选择，启动记录给出完整的 `--runtime-llvm-jit-policy` 参数。应使用实际应用和 CPU 配额分别测量冷启动与稳定运行性能。

全内核测试区分三种权限结果。开放 ABI 查询时运行 SDK 应用，显式拒绝时由专用 Wasm 程序核实调用返回 13，省略该接口时核实 VM 在应用入口执行前拒绝链接。

要验证 SDK 应用自身的双重验签，先向测试签发工具 `tests/wsea_preflight.py` 传入 `--sdk-module FILE --sdk-source TRUSTED_SDK_CHECKOUT`，再把生成的 `bundle/sdk.signed.wasm` 作为 `tests/qemu_supervisor.py` 的 `--signed-sdk-module`，并提供原始未签名测试输入。部署器验签并只读核对其防回滚状态，VM 独立验签并在自己的防回滚存储中记录接受的模块版本。测试比较部署器状态在执行前后的摘要，并读取 VM 的版本记录。签名私钥保留在来宾之外。

当前 VM 将 ROSv2 导入归入 WSEA 的其他原生导入类别（掩码 32）。测试签发器先检查待签的同一份字节，只接受唯一的 `uwvm_ros_v2.abi () -> i32` 导入。部署时还需要单独开放该接口。应用签名、VM 验签策略与 XML 权限推荐文件分别管理。

### 按 VM 审阅只读时钟

Preview 1 时钟读取需要分别批准导入函数及允许读取的时钟来源。例如，wasm32 程序读取单调时间时，可以在该 VM 的独立推荐文件中写入以下内容。

```xml
<recommendations>
  <interface name="wasip1.clock_time_get" expose="allow"/>
  <wasip1-clock name="monotonic-clock" access="allow"/>
</recommendations>
```

wasm64 目标使用 SDK 对应的 `wasip1.clock_time_get_wasm64`。读取分辨率使用 `wasip1.clock_res_get` 或 `wasip1.clock_res_get_wasm64`。时间读取权限包括 `realtime-clock`、`monotonic-clock`、`process-clock`、`thread-clock`，另有四个以 `-resolution` 结尾的分辨率读取权限。交互式审核使用 `wasip1.clock.monotonic-clock` 这样的键。省略接口时 VM 默认隐藏它。显式拒绝的接口可完成链接，调用返回权限错误。允许接口后仍需授予所选时钟来源和操作的权限。部署器只为该 VM 生成配置，原有 ROS 接口的推荐名称继续有效。受保护的审批记录保存每项决定，以便冷启动。时钟批准不会授予定时器、文件或网络访问权。

## 联合测试 SDK、VM 与部署器

使用已导入站点配置的 C 开发安装。测试先用安装的头文件编译程序，核对 SDK 与部署器的接口清单，再使用临时测试证书签名，并在独立的 x86_64 Linux 来宾中运行所选 VM 引擎。串口日志逐项列出 ROS 接口授权决定。为每次运行指定新的输出目录和独立的私有测试证书目录。签名私钥保留在宿主，测试在验收 cgroup 内执行。

```sh
/usr/bin/python3 tests/sdk_vm_deployment.py \
  --sdk "$INSTALLED_SDK" --vm "$VM" --vm-source "$VM_SOURCE" \
  --deployer "$DEPLOYER" --cosign "$COSIGN" --engine aot \
  --kernel "$KERNEL" --qemu "$QEMU" --bios "$BIOS" --firmware-directory "$FIRMWARE" \
  --output "$DEPLOYER_SOURCE/.tmp/site-aot" --authority-directory "$VM_SOURCE/.tmp/site-test-keys"
```

测试另一种 SDK 语言时，使用 `--sdk-abi-application FILE` 指定已编译的 ABI 查询程序，使用 `--approved-build-receipt-sha256 DIGEST` 指定操作员已审核的相邻 `FILE.wros-build.json` 的摘要。该用例仅接受 `uwvm_ros_v2.abi` 导入。它先校验产物与 VM 的匹配关系，再对私有副本签名，随后在 QEMU 来宾中验证部署器和 VM 的两次验签。

完整签名部署测试可指定 `--accelerator tcg`（默认）或 `--accelerator kvm`，还可用 `--guest-timeout-seconds` 设置整个来宾的时限，取值 30 至 1800 秒，默认 240 秒。所选后端需要当前 cgroup 允许。两次 TCG 测试均从各自语言公开安装的 SDK 构建应用，使用 AOT 引擎、fast-compile 策略和 1200 秒来宾时限。编入 Wasm 的 Lua 解释器在 499 秒内通过全部 42 项检查，Fortran 应用在 1036 秒内通过相同的 42 项检查。来宾会分别启动新的 VM 来验证授权、拒绝和签名，时限包含这些进程的编译和监督时间。

D BetterC 使用所选安装中的 `wrd verify` 核对操作员批准的构建回执、Wasm 和 VM，随后才签署应用。公开 SDK 提交 `5fa860a356f19ed29aea514142eb897c3231951f` 的 Unitree D 安装包构建的 Xmake 示例，在 QEMU TCG 解释器部署中通过了全部 42 项用例，包含部署器和 VM 独立验签。该应用只导入 `uwvm_ros_v2.abi`。

### ROSv2 本地调度资源

在各 VM 独立的推荐权限 XML 中，为每个具名资源单独配置操作。下面的来宾可以打开 `signal`、创建并触发 guard。它调用已经暴露的 `guard.take` 时会收到拒绝。

```xml
<recommendations>
  <interface name="capability.open" expose="allow"/>
  <interface name="guard.create" expose="allow"/>
  <interface name="guard.trigger" expose="allow"/>
  <interface name="guard.take" expose="allow"/>
  <local-resource type="guard" alias="signal" operation="guard.create" access="allow"/>
  <local-resource type="guard" alias="signal" operation="guard.trigger" access="allow"/>
  <local-resource type="guard" alias="signal" operation="guard.take" access="deny"/>
</recommendations>
```

| 资源类型 | 可独立授权的类型专属操作 |
| --- | --- |
| `guard` | `guard.create`、`guard.trigger`、`guard.take` |
| `clock.steady`、`clock.system` | `clock.create`、`clock.read` |
| `clock.ros` | `clock.create`、`clock.read`、`clock.update` |
| `timer` | `timer.create`、`timer.reset`、`timer.cancel`、`timer.take` |
| `wait` | `wait.create`、`wait.add`、`wait.remove`、`wait.acknowledge`、`wait.poll` |

每种资源还可以独立授权 `resource.observe`、`resource.close` 和 `capability.revoke`。来宾调用的导入接口需要单独暴露。其他操作引用该资源时，VM 可以检查其 `resource.observe` 权限。创建定时器时 VM 还会校验时钟权限，向等待集合加入资源时会校验该资源的观察权限。

在审核界面输入 `allow local/guard/signal/guard.create` 可以添加一项操作。部署器将批准的操作合并为该别名的一条本地授权。没有获准操作的别名无法打开。同一个 VM 中的别名只能绑定一种类型。经授权冷启动时，部署器从受保护的状态记录恢复已审核的操作，VM 重新创建句柄。这条路径只启用 ROSv2。

### 审阅权限报告和元数据

绑定到 ROSv2 的模块默认可以查询自身权限。可以在该进程的推荐权限文件中按模块族或具体函数限制报告内容。查询其他模块的声明或 VM 运行时状态时，要分别审阅接口和针对指定对象的授权。

```xml
<recommendations>
  <self-report selector="wasip1.fd_write" access="deny"/>
  <self-report selector="preloaddl" access="deny"/>
  <interface name="module.exports" expose="allow"/>
  <metadata type="module" alias="worker-view" target="worker" operation="module.exports" access="allow"/>
  <interface name="vm.describe" expose="allow"/>
  <metadata type="vm" alias="runtime-view" target="runtime" operation="vm.describe" access="allow"/>
</recommendations>
```

若某个函数的查询被拒绝，VM 也会拒绝能够披露该函数的整族查询。选择器上的 `allow` 表示该项不追加限制。整族拒绝和 `permission.report` 接口本身的暴露规则仍然生效。支持的模块族有 `preloaddl`、`preloadwasm`、`wasip1`、`ros1v1`、`ros2v1` 和 `rosv2`。查询可返回当前构建缺少相应支持的状态。

读取模块描述、导入、导出、反向导入关系、权限组和权限报告分别对应 `module.describe`、`module.imports`、`module.exports`、`module.importers`、`module.group` 和 `module.permission.report`，需要逐项审阅。VM 状态使用固定对象 `runtime` 和操作 `vm.describe`。客体查询时传入已批准的别名。每个别名在一个进程内绑定唯一类型、对象和用途。这些权限均为只读。交互审阅使用 `report/选择器` 和 `metadata/类型/别名/对象/操作`，冷启动时恢复已审阅的决定。

选择恢复模块前，可在本地校验其 MVP 入口、导入和资源上限。[恢复模块预检](recovery-preflight.md)
