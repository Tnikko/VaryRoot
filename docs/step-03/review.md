# 步骤 03 复核 · Ubuntu 24.04 实验机

正式工作目录为 tq@192.168.32.128 的 /home/tq/varyroot。VMware 客体有 4 个 vCPU、7.7 GiB 内存，/home 位于 196 GiB 的 ext4 根卷，复核后约有 168 GiB 可用。宿主运行器使用用户目录内的 CPython 3.13.2，系统自带 Python 3.12 保留。Docker Engine 29.1.3 由 Ubuntu 软件包安装，systemd 服务为 active、enabled。协调器以 tq 运行，本次仅通过 sudo 调用 Docker；角色容器进程使用 1000:1000。没有为 tq 增加 docker 组成员资格。[运行环境](vm-environment.txt)

## 迁移与构建

Windows 项目保留原件。经 WSL2 ext4 迁入虚拟机时，项目按字节传输，源目录中的 api.txt 留在 Windows，虚拟机副本排除了 Python 字节码缓存。对照迁移清单核实了 392 个原项目文件。新加的 .gitattributes 规定新源码和 JSON 夹具使用 LF。原有冻结材料在迁移时未重写。先重跑里程碑 I 的 20 项测试、validate 和 explain，再进行本步集成。[VM 基线输出](vm-baseline.txt) · [迁移字节摘要](vm-migration.sha256)

迁移初期发现 Windows Docker Desktop 的启动器缺少安装注册项。WSL 预检和正式虚拟机均采用各自原生 Linux Docker Engine。基础镜像是 Docker 官方 python:3.13-slim 的 linux/amd64 版本，通过 Windows 本地 7900 代理取得并核验清单与层摘要，再离线导入虚拟机。虚拟机拉取此次镜像不依赖 Windows 桥接代理，后续下载新镜像的网络条件需单独确认。角色镜像只从显式源文件清单构建。运行前解析镜像 ID，各容器按同一不可变 ID 启动。[构建记录](vm-build.txt)

## 四条文件事件链

完整文件流、各阶段摘要、收据、门禁结果及每组 SQLite 账本保存在虚拟机 runs/step03-final/ 下。四条独立测试运行分别用各自账本，序号仅在对应账本内比较。下表中的冻结号属于 test: 命名空间。[四条完整事件链](vm-events.json)

| 测试路径 | A／预测 → 验证器 → B | C 与终态 |
| --- | --- | --- |
| 修订 | 两版输入通过真实 validate。真实 explain 在同一目标产生 quiet、report；登记后扣费并选例，独立区间桩给 positive。B 输出 revise 和非空 Revision | Q₀ 模拟实测 FN，Q* 模拟实测 TP，双版门禁通过，测试冻结 |
| 保留 | 两份输入绑定同一规约版本，均预测 report。positive 揭示后 B 输出 keep，显式 revision_ref=null | 两版均为 TP，测试冻结 |
| 未决 | 正常触达的有限观察缺覆盖，验证桩给 pending。B 输出 unresolved，显式空最终规约与修订引用 | 没有创建 C 视图，未签发编号，验证预算扣一次 |
| 后端缺口 | 真实预测从 quiet 变为 report；positive 揭示后 B 修订。C 接到独立的模拟数据库输出 | Q* 在可计分位置得到 no_alert，计 FN 并保留 width_unavailable，整体 partial，无编号 |

四条链均在本账本的事件 6 登记预测、事件 8 记费、事件 14 揭示。修订、保留、缺口链各记录 20 个事件，未决链 17 个。A 和 B 使用独立进程的真实里程碑 I CLI；B 产出的版本化交接包再次经校验，C 对输入重新验包。种子接受、独立验证的执行语义及双查询实测在本步使用合成契约桩。

## 并发、故障与隔离

- SQLite 使用 WAL、FULL、busy_timeout=15000 及 BEGIN IMMEDIATE。并发提交同一选择或同一修复只有一条费用项；变更重试键参数、伪造候选成员或输入摘要的请求在事务内拒绝。真实 SIGKILL 在提交前触发时，重开数据库看不到半笔费用或派发项。
- 发布恢复检查了 T1 前、T1 后、目标临时文件写到一半、正式对象已提升但 T2 未提交，以及 T2 后。半写杀进程时保留 publishing，读取正式结果受阻；恢复从已校验的封存内容补齐发布。同摘要重复回执幂等，不同有效结果冲突阻断；已作废尝试的迟到回执无法推进当前请求。正式路径按内容寻址，临时文件刷盘后以同卷硬链接创建新名称，无需覆盖已打开的文件。
- 业务退出码 2、3、4 终止本次业务输入，5 和异常进程退出在上限内按原逻辑请求重试。测试包含真实的冲突和强杀，以及模拟 Docker 125–127 的子进程退出码。
- 7 个真实容器检查 A、验证器、B、C 编译、C 回归、随机选择与分歧选择视图。每个容器仅挂入已核对摘要的白名单副本（只读）和本尝试输出目录（可写），没有 Docker socket 或外部网络。未列对象、未来标签及另一组标签不可读。随机选择器的真实算法与其输入派生仍由 06 验收。[完整测试输出](vm-final-tests.txt)
- R02、R03 本步通过。R04 保留待验，未注入真实电源故障。R05 协调器部分通过，06 再验真实选择器。[台账](../runtime-acceptance.md)

首次集成发现角色桩的 JSON 输出带空格与换行，与收据的规范字节编码不一致，已统一编码并重建镜像。复核还补上了冻结池成员的逐项验证、角色契约错误的不可重试路由，以及从生成角色输入到提交预测期间的证据水位检查。

## 实际复核与重放

在虚拟机的项目根执行。Docker 需要 sudo 时先在同一终端运行 sudo -v。最后一行可指定尚不存在的目录以保留四条文件链；未设置时端到端测试使用临时目录。

~~~bash
cd /home/tq/varyroot
export PATH="$HOME/.local/bin:$PATH"
export PYTHONDONTWRITEBYTECODE=1 VARYROOT_DOCKER_SUDO=1 VARYROOT_R05_DOCKER=1
sudo -v
varyroot-python3.13 -c 'from varyroot.sandbox import build_image; build_image()'
VARYROOT_TRACE_DEST="$PWD/runs/step03-final" varyroot-python3.13 -m unittest discover -s tests -v
~~~

本次最终运行 54 个测试方法，全部通过，耗时 28.710 秒。再次运行时选择新的 VARYROOT_TRACE_DEST，保留原验收链。原始故障发布测试在临时目录执行，每次均从相应中断点重开账本。

## 步骤 04 待审实施计划

1. **源码快照与前端。** 在 Ubuntu 上锁定 Clang、语言模式、编译参数和快照摘要。为受控 C/C++ 源码片段输出可反查的 UTF-8 半开跨度、拼写位置、展开位置、作用域与访问角色。验收同行双访问及字符边界。
2. **映射与事实。** 用确定性程序区分唯一、一对多与歧义；给每条 Fact 登记来源、对象代次、路径和契约。用宏实参重复使用、内联上下文和错误对象容量检查，保存无法核准的位置与原因。
3. **Agent A 交接。** 局部提案经输入白名单接收，输出骨架、映射、假设、S₀ 与候选解释。真实调用 01/02 接口，产出 seed_pending；已登记的退出和状态恢复应分别可解释。由 05 独立证据接通接受门禁。
4. **回退与复核。** 走查 B4 → A2、B4 → A5 的版本依赖、初始基线、水位与剩余额度。复跑本步与全部既有回归，附 Clang 版本、映射逐例结果及 R06 的前端分项；跨 CodeQL 对齐留给 07。
