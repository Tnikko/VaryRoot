# 步骤 07 运行命令

工作目录为 Ubuntu 虚拟机的 `/home/tq/varyroot`。以下命令使用 VM 上已有的离线镜像和 CodeQL 工具树。安装的镜像与 pack 摘要见 [环境锁](runtime-lock.json)。冻结包内的 `build-log.json` 和 `database-build-log.json` 保存实际执行的 argv、退出码与标准输出。

## 全量与轻量回归

```sh
export PATH="$HOME/.local/bin:$PATH" PYTHONDONTWRITEBYTECODE=1
export VARYROOT_DOCKER_SUDO=1 VARYROOT_R05_DOCKER=1 VARYROOT_R06_DOCKER=1
export VARYROOT_R07_DOCKER=1 VARYROOT_R08_DOCKER=1 VARYROOT_STEP06_DOCKER=1 VARYROOT_STEP07_DOCKER=1
export VARYROOT_REPLAY_TEST_IMAGE=$(cat docs/step-07/runtime-image.txt)
export VARYROOT_C07_SIGNED=$PWD/runs/step07-release-npd/store
export VARYROOT_07_TRACE=$PWD/runs/step07-full-2/upstream VARYROOT_B_TRACE=$PWD/runs/step07-full-2/b
export VARYROOT_05_TRACE=$PWD/runs/step07-full-2/verifier VARYROOT_TRACE_DEST=$PWD/runs/step07-full-2/legacy
export VARYROOT_SEED_TRACE_DEST=$PWD/runs/step07-full-2/source
sudo -v
varyroot-python3.13 -m unittest discover -s tests -v >docs/step-07/vm-final-tests.txt 2>&1
```

复跑应将五个 trace 目的地改到新的空目录，防止新测试重用上一轮的临时账本。需要快速检查纯坐标与五列回归时，分别运行以下用例。

```sh
varyroot-python3.13 -m unittest discover -s tests -p test_coordinates07.py -v
varyroot-python3.13 -m unittest discover -s tests -p test_agent_c07.py -v
```

## 生产提交、已签发包重放和实测中断

生产入口按 B6 已提交账本读取。独立验收入口 `tools.codeql07.acceptance` 提交前先用 SQLite backup 取得账本副本，允许源步骤的已批准账本保持原序号。以下命令示例消费已登记的测试工件，目标目录需为本轮新建目录。

```sh
tools=$PWD/toolchains/codeql-2.27.2
img=$(cat docs/step-07/runtime-image.txt)
varyroot-python3.13 -m tools.codeql07.acceptance runs/step06-final/test_oob_keep oob.divergence runs/step07-new-keep "$tools" "$img" --reuse runs/c07-oob1/artifacts --repair-from runs/c07-oob1/artifacts
```

已签发包可直接重放。此处的摘要取自生产回执。导出的 `release/…/archive` 可以移动。输出目录必须为空。

```sh
sudo -v
sudo -n python3 tools/codeql07/replay.py docs/step-07/release/revise/archive 8724fcc78a5fe9eb7b5f9fd7fdd2a4dcbd805c99279160772ae93c2042bad86f "$tools" "$PWD/runs/replay-revise-new"
sudo -n python3 tools/codeql07/replay.py docs/step-07/release/keep/archive 15af5930bda8163a1cb87e0af8010319d00cbe8b45f56394f924e6ffdb98f818 "$tools" "$PWD/runs/replay-keep-new"
varyroot-python3.13 -m tools.codeql07.interruption runs/step07-release-npd/c/artifacts runs/c07-npd1/build/db "$tools" runs/step07-interrupted-new
```

坐标微基准使用独立的前端与位置查询，命令见 [坐标验收](alignment.md)。所有引用的路径和摘要都可在复核包根目录运行 `sha256sum -c SHA256SUMS` 核验。
