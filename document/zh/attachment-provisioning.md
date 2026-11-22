# 本机加密通道的安全交付

Rust `attachment` 模块为已经获准的 VM 与外置服务建立独立会话。它负责生成密钥、
固定进程身份和交付不可变启动记录。正式 `run` 路径为每个驱动可执行文件声明建立独立认证会话，每个声明绑定一个 VM。同一 VM 可以接入多个只读提供方，各自使用独立别名、UID、GID、cgroup 和互不重叠的沙箱根目录。VM 的 XML 属性 `driver-budget-bytes` 限制这些路由在 VM 侧的预留内存总和。每个提供方也必须满足其单独的内存预算。进程的 argv[0] 为驱动 ID，后续参数依次为交付描述符、管理进程 PID、
UID、GID 及固定的 `read-only`。
`tests/support/attachment_provisioner.rs` 仅是测试用调度程序。

## 交付流程

1. 受信部署器先预留宿主身份与资源，完成独立 cgroup、最终 UID/GID 和命名空间设置。
   之后安装禁止改变命名空间的约束。所有原生代码都在 VM 进程之外。
2. 每次会话使用 Linux `getrandom` 生成两份独立的 32 字节种子，并由固定版本
   `ed25519-dalek` 2.2.0 生成公钥。内核随机源不可用就拒绝创建，禁止时间、PID 或弱随机回退。
3. 两端分别获得 64 字节密封 memfd，内容是自身种子及对端的准确公钥。文件权限为
   0400，同时禁止写入、增长、缩短和改变封印。临时敏感缓冲与私钥对象销毁时清零。
   memfd 内容直到最后一个描述符关闭才由内核回收；封印不代表物理擦除，也不防宿主 root。
   密钥不得进入 XML、命令行值、环境变量、日志或 Wasm 内存。
4. 传输使用提前连接的匿名 AF_UNIX SOCK_SEQPACKET，预先开启 SO_PASSCRED，默认
   非阻塞且 exec 时关闭。部署器只向对应进程继承指定描述符，交付后不保留额外收发端。
   Wasm 无法选择监听地址或其他部署的服务。
5. `Peer::pin` 核验真实、有效、保存及文件系统 UID/GID，保留 pidfd，并读取该进程的
   时间命名空间。前后均要求进程存活且与部署器共享单调时钟。调用方必须已经固定
   命名空间；观察到一个 inode 并不能证明对端安装了指定 seccomp 规则。
6. 确定双方 PID 后，生成并封印准确绑定身份、部署、VM、模块范围、服务代次、随机
   会话、协议摘要、有限预算及内核对象身份的启动记录。VM 的完整参数使用同一绑定。
7. 外置适配器在专用继承通道发送 `WROS-READY`。部署器检查消息及内核提供的准确
   PID/UID/GID，拒绝额外辅助数据并关闭所有夹带的描述符。随后发送 `WROS-FDS`，
   按顺序交付传输端、密钥、对端时钟、启动记录四个描述符。交付时间有限，最长五秒。
   这是内核保护下的信任初始化，不是面向应用的明文服务。
8. 适配器核验部署器凭据、描述符数量和 `provider_bootstrap::load`，关闭交付通道，
   再启动现有双向 TLS。启动记录与 TLS 均不授予业务权限，也不证明物理安全状态。
   VM 权限和外部受信接收端的独立准入仍然必需。

目前仅接受 TLS 1.3、准确绑定的 Ed25519 原始公钥、临时 X25519 和 AES-128-GCM。
TLS 标签绑定部署、VM、模块范围、服务、会话和协议摘要。未知密码配置立即拒绝。
未来的配置必须在双方实现并经过策略准入，禁止降级回退。业务消息继续加密并逐包检查内核凭据。

## 固定启动记录

记录恰好 256 字节，标量均为小端 u64，不包含指针或原生结构体布局。

| 偏移 | 字节 | 内容 |
| --- | --- | --- |
| 0 | 8 | `WROSDRV` 后接 NUL |
| 8 | 8 | 长度 256 |
| 16 | 8 | 服务类型 1：驱动 |
| 24 | 8 | 密码配置 1：上述固定 TLS 配置 |
| 32 | 24 | 适配器 PID、UID、GID |
| 56 | 24 | VM PID、UID、GID |
| 80 | 80 | 部署、VM、模块范围、服务、会话，各 16 字节 |
| 160 | 32 | 协议 SHA-256 |
| 192 | 32 | 请求字节数、响应字节数、请求时限、会话到期时间 |
| 224 | 16 | 适配器传输端的内核设备号与 inode |
| 240 | 16 | 对端时间命名空间的设备号与 inode |

请求和响应分别限制为 1–65536 字节。时间值必须非零且不超过 INT64_MAX，过期即拒绝。
PID 必须是正的有符号 32 位值，双方进程必须不同；UID/GID 不接受全一无效值。
所有标识和摘要不得全零。解析器在完整校验后才更新输出；加载时进一步验证封印、
类型、长度、本进程身份和内核对象身份。后续通道仍独立检查命名空间类型、pidfd、
socket 属性、逐包凭据和双向 TLS。

记录没有命令、路径、FFI 地址、程序镜像、文件授权、信号、重启或更新操作。
更换服务代次需要重新准入并生成新会话，Wasm 不能通过已连接通道完成这些操作。

## 测试与边界

适配器可使用 VM 仓库中仅供外部宿主调用的 `provider_bootstrap_receiver.h`。
`receive` 发送就绪消息，用 pidfd 固定部署器进程，验证内核凭据、四个描述符和封存记录，
全部通过后才交付结果。预期 PID/UID/GID 必须来自受信启动配置，不能从收到的消息中采信。
超时范围为 1–5000000000 纳秒；函数借用 courier，不改变原描述符的标志或选项。
失败、截断和多余的 SCM_RIGHTS 描述符均被关闭，已有记录输出保持不变。
不可复制的 `descriptors` 对象持有四个交付对象；访问器仅供借用，TLS 完成初始化后调用
`reset()` 关闭原始对象。函数不分配堆内存，也不编入 VM 的执行入口。

交付双方均用固定大小辅助数据缓冲区容纳 Linux 单条消息最多 253 个描述符，随后显式
关闭并拒绝多余对象，不依赖用户态模拟器代为清理截断后未交付的句柄。

`tests/attachment_provisioning.py` 用真实 VM 和独立 C++ 无害参数查询端测试正常交付、
错误密钥、会话混淆、描述符替换、未知配置、畸形就绪消息、对端退出、夹带描述符和
其他进程伪造来源，同时检查部署器描述符数量。代码以优化和调试符号同时开启的配置构建。
`tests/attachment_protocol_abis.py` 在五个 Linux ABI 执行解析测试，并运行 ASan/UBSan。
选项 `--suite receiver` 进一步执行 19 项实际内核交付测试，覆盖凭据伪造、最大数量描述符注入、
对象替换、缺少封印、过期记录、错误通道类型和限时退出，并检查实际描述符数量及失败后输出不变。
`tests/linux_abi.py` 验证 Rust 密钥生成及已有部署契约。

`tests/qemu_attachment_provisioning.py` 在离线临时内核内使用不同非 root 身份、独立
网络命名空间与嵌套 cgroup 重复真实 VM 测试。来宾无物理设备、宿主磁盘或共享目录。
测试部署器在双方启动前为其空 cgroup 安装[固定设备基础规则](device-isolation.md)，
每个场景使用新组，不替换已有内核规则。这验证加密 IPC 能在设备限制下工作，
不代表已授予真实厂商硬件权限。
所有测试仍受宿主现有 64 GiB、零 swap cgroup 限制。这些结果不代表厂商驱动普遍兼容、
真实停机验证、设备唯一所有权或工业安全认证。
使用 `--receiver-checks` 指定原生接收边界测试程序，可在来宾内核中另外执行其 19 项检查。
Rust 契约测试也检查就绪包夹带 253 个描述符时全部关闭并拒绝。
该组件测试提供受控的时钟证据，实际执行 pidfd 和描述符交付；命名空间类型准入由
完整内核测试单独覆盖。生产代码仍拒绝用户态模拟器未实现的命名空间 ioctl，不跳过检查。

密钥生成、封印与启动记录解析仅在准入阶段执行，不进入逐消息调用路径。
不得把冷启动开销混入 native/Wasm 稳态往返对比，也不得把测试调度程序称为完整生产部署器。

验收脚本同时核验 OpenSSL 静态库摘要、依赖构建记录及 VM 的编译和链接命令。
加密依赖本身也必须使用 `-O3 -g`；只在调用方保留调试信息不足以定位依赖源码和汇编。
硬件采样针对长时间重复调用，事件计数周期不代表固定的墙钟采样间隔。

### 宇树 Go2 原厂遥测

`tests/vendor_unitree_qemu.py` 使用校验 SHA-256 的本地 Unitree SDK 2.0.2 归档。
离线来宾运行上游 HelloWorld 两端，并通过该版本的原厂 DDS 库交换 Go2
`LowState`。测试以临时 Ed25519 密钥签署可执行文件和库的清单。来宾在启动原生
进程前验签，并验证修改过的清单会被拒绝。

启用认证连接验收时，`wrwat` 编出带 WasmMTE 的来宾模块。测试用临时证书签发
WSEA 签名。部署器和 VM 使用独立的防回退状态分别验签。Rust 测试程序向独立非
root 进程交付全新的 TLS 凭据及封存的启动描述符。Go2 适配器通过官方 SDK
读取一个关节的遥测样本，并限于此次定长读取。VM、适配器和仅使用回环网络的
DDS 发布端分别进入独立 cgroup。解释器和 AOT 都在 Wasm 内校验收到的 DDS
样本，并验证篡改的 Wasm 和错配的 TLS 对端密钥会被拒绝。

用 `--help` 查看认证连接和 QEMU 的参数。将 `--signing-scratch` 指向 VM
磁盘 `.tmp` 内当前用户私有的目录，在 64 GiB、零 swap 的 cgroup 内运行。
回执记录上游归档、执行文件及编译输入的摘要和来宾检查结果。发布端在来宾内
生成固定遥测数据。实体 Go2 和生产部署器的原厂驱动启动需要单独验收。

`tests/vendor_unitree_mujoco.py` 单独验收原厂仿真路径。它在 MuJoCo 3.4.0
加载固定版本的官方 Go2 模型并运行宇树原厂 Python DDS 桥。独立编译的原厂
C++ SDK 订阅端与原厂 Python SDK 订阅端分别检查关节位置、IMU 四元数和机身
位置。测试为仿真及订阅端的输入签名，验签后在只有回环接口的网络命名空间
运行。测试采用无界面模式并关闭手柄输入。用 `--help` 指定模型及来源记录、
两份固定的原厂桥文件、本地 SDK 源码和 Python 依赖目录。Cyclone DDS 0.10.2
的 Python 绑定需链接 SDK 自带的 Cyclone 库。Python 依赖目录须包含 MuJoCo
3.4.0、NumPy 和 Pygame。

[Unitree SDK 2.0.2](https://github.com/unitreerobotics/unitree_sdk2/releases/tag/v2.0.2) ·
[宇树 MuJoCo 桥](https://github.com/unitreerobotics/unitree_mujoco/tree/1eb6642e3f3fdfb7fb13a9794fd6a2dd93ea0e7d)

### Universal Robots Client Library

`tests/vendor_universal_robots.py` 校验本地 Universal Robots Client Library
2.16.0 和 GoogleTest 1.17.0 归档，以开启优化和调试行号的配置编译上游离线
测试。测试程序用临时 Ed25519 密钥签署原生测试程序、库和 CTest 执行计划。
每个测试程序在独立且仅有回环接口的网络命名空间运行，启动前复核签名和摘要。
独立命名空间避免早先的测试占用后续用例的固定端口。

离线套件共登记 673 项，覆盖 RTDE 协商和遥测、重连、指令序列化、Primary 和
Dashboard 协议及轨迹接口。回执记录用例名称、状态与签名文件摘要。可使用
`--suite rtde` 聚焦解析器和 RTDE 客户端。URSim 和 ROS 硬件驱动还需匹配的
控制器版本进行联调。

```sh
systemd-run --user --scope -p MemoryMax=64G -p MemorySwapMax=0 \
  python3 -B tests/vendor_universal_robots.py \
  --archive "$PWD/.tmp/urcl-2.16.0.tar.gz" \
  --gtest-archive "$PWD/.tmp/googletest-1.17.0.tar.gz" \
  --output "$PWD/.tmp/urcl-offline"
```

[Universal Robots Client Library 2.16.0](https://github.com/UniversalRobots/Universal_Robots_Client_Library/releases/tag/2.16.0)
