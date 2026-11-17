# Wireshark 扩展与教学协议

实际验证版本为 Wireshark/TShark 4.6.9、Lua 5.4.6。源码包含 labdemo.lua、labproc.lua、labdemo_stats.lua 和 vendor 下的 dkjson、sha2。后两者是保留许可证的第三方源码。

## 加载和卸载

推荐本次启动按文件加载。启动器优先使用显式设置的 TSHARK_PATH、WIRESHARK_PATH，其次查找 `%LOCALAPPDATA%\UCAS-NetLab\Wireshark`、系统安装目录、项目 portable 目录和 PATH。GUI 与测试共用同一个查找函数。本机实际使用 `%LOCALAPPDATA%\UCAS-NetLab\Wireshark` 中的 4.6.9；交付 ZIP 不包含 Wireshark 安装包。

```powershell
.\open_wireshark.ps1
.\open_wireshark.ps1 -Capture '.\samples\real_http.pcap'
.\open_wireshark.ps1 -Capture '.\samples\real_http.pcap' -TShark
```

省略 Capture 时打开包含网卡列表的欢迎界面，可以直接选择 loopback 开始实时抓包。指定 Capture 时，样例的实际名称见 samples/样例清单.json，以上名称需替换。启动器先校验配套 JSON，再通过 -X lua_script 参数加载三个脚本，自动传入 labproc.metadata 和 labproc.capture 的绝对路径。关闭此实例即可卸载本次加载；直接启动 Wireshark 可执行文件时不会自动加载这些项目脚本。

本机 2026-11-17 排错记录：系统 ANSI 代码页为 936。三个 Falco DLL 在中文路径下通过 LoadLibraryW 和系统代码页字节加载均成功，向 LoadLibraryA 传入 UTF-8 路径时均返回错误 126。将同一份完整 Wireshark 4.6.9 部署到上述英文目录后，TShark stderr 中的加载警告消失，cloudtrail、gcpaudit、k8saudit 和两个课程协议全部注册成功。Wireshark.exe 的 Wireshark Foundation 签名有效，复制前后的核心程序和三个 Falco DLL 摘要一致。

默认桌面配置与独立验证配置均已显示 11 个本机接口，包括 WLAN、以太网和 loopback。通过 GUI 实际捕获 54 个本机 HTTP/UDP 包，并通过工具栏停止按钮结束捕获；自研采集器同步保存的报文字节逐包一致。LABDEMO 识别 8 个包，包含两个预期异常消息；本次 PID 72792 的元数据过滤得到 36 个包、3 条 TCP 流。没有配套信息的 Wireshark 原生捕获显示 unknown_no_metadata。原始日志和辅助功能控件记录保存于开发目录 output/wireshark-repair，交付副本位于 evidence/acceptance/evidence/wireshark-desktop。

需要长期安装时，在 Wireshark“帮助 → 关于 → 文件夹”找到个人 Lua 插件目录，创建 ucas_ex1a 子目录，将三个 Lua 文件和 vendor 子目录完整复制进去，重启 Wireshark。在“分析 → 启用的协议”中检查 labdemo、labproc。采用长期安装方式时，直接启动 Wireshark，并在“首选项 → Protocols → LABPROC”设置配对 PCAP 和 JSON；不要同时使用带 -X 的项目启动器，以免重复注册。卸载时删除自己创建的 ucas_ex1a 目录并重启。上述长期目录复制与 GUI 菜单操作未在本次自动验收中执行；本次实际验证采用 -X 进程内加载。

TShark 进程字段需要两遍解析，并要求第一遍生成协议树：

```powershell
$capturePath = (Resolve-Path '.\实际样例.pcap').Path
$demoScript = (Resolve-Path '.\wireshark\labdemo.lua').Path
$procScript = (Resolve-Path '.\wireshark\labproc.lua').Path
& $env:TSHARK_PATH -2 -R 'frame.number >= 1' -r $capturePath -X "lua_script:$demoScript" -X "lua_script:$procScript" -o "labproc.metadata:$capturePath.labproc.json" -o "labproc.capture:$capturePath" -Y 'labproc.pid' -T fields -e frame.number -e labproc.pid -e labproc.name -e labproc.status
```

GUI 完整载入后应用显示过滤，或使用“Tools → UCAS → Refresh process fields”。校验尚未完成时显示 pending_full_capture_validation，PID 保持空白。刷新操作重新应用过滤，使用同一文件的完整校验状态。重新载入和首选项变更调用 init/prefs_changed 重置。无元数据时显示 unknown_no_metadata。

## LABDEMO 报文

一个 UDP 数据报承载一个消息，头部固定 12 字节，全部多字节整数使用网络字节序。默认服务端端口 45990，可在插件首选项调整，合法魔数也可经 UDP heuristic 识别。

| 字节偏移 | 长度 | 字段 | 约束 |
| --- | ---: | --- | --- |
| 0 | 4 | magic | ASCII LAB1 |
| 4 | 1 | version | 1 |
| 5 | 1 | type | 1 请求、2 成功响应、3 错误响应 |
| 6 | 4 | request_id | 无符号 32 位，请求和响应保持一致 |
| 10 | 2 | payload_length | 0–4096，必须与剩余数据长度完全一致 |
| 12 | payload_length | payload | 字节载荷；教学工具以 UTF-8 文本演示 |

错误魔数保留为普通 UDP，具有 LAB1 魔数但头部不足、版本错误、长度不符或类型未知的报文显示 LABDEMO 异常与 valid=false。同端口上的任意字节不会自动成为有效协议。正常服务端回复 ACK:载荷；未知类型返回 type=3；非法魔数和非法长度不响应。教学工具的 timeout 载荷故意不响应，用于超时演示。

请求载荷允许达到 4096 字节；加上 ACK: 后超过响应长度上限时，服务端返回 type=3、载荷 response too large，并继续处理后续请求。

过滤例子：`labdemo.type == 1 && labdemo.valid == 1`、`labdemo.request_id == 1001`、`labdemo.valid == 0`。Wireshark 中单独写布尔字段名称检验字段是否存在；检验真假时明确比较 1 或 0。

| 样例 | 期望 |
| --- | --- |
| 正常请求/响应 1001、1006 | type=1/2；ID 一致；valid=true |
| 错误魔数 1002 | 普通 UDP；不产生 labdemo 字段 |
| 声明载荷 100 字节、实际 3 字节 1003 | invalid_length；valid=false |
| 未知 type=99、ID=1004 | unknown_type；服务端产生 type=3 错误响应 |
| 请求 1005，载荷 timeout | 捕获后续有效报文时间超过 2 秒后统计为超时 |
| 只有 LAB1 与额外一个字节 | header_truncated；离线边界样本 |

## 进程配对

PCAP 保存原始报文字节和原始时间戳；JSON schema=1 保存 session_id、PCAP SHA256、linktype、packet_count 与有序 packets。每个包记录 original_number、timestamp_ns 字符串、caplen、wirelen、原始数据 SHA256、stream_id、process.status 和 owners。每个 owner 包含 pid、name、created、local、remote、sample_started_ns、sample_ns；process 还记录 associated_ns。纳秒值用十进制字符串避免 JSON/Lua 浮点精度损失。

SQLite 内 frame 是保存顺序，original_number 是原始捕获编号；采集队列丢弃后编号允许有缺口。重新导入和导出保持会话 UUID 与原始编号。导出完整会话不受显示过滤影响。

Lua 先计算指定 PCAP 的完整 SHA256，再逐帧校验当前打开文件的编号、长度、时间戳与原始字节摘要。只有全部帧通过且进入重复解析才公开 PID，防止把另一个文件或过滤导出文件关联到原元数据。没有元数据、摘要不符、包数不符或某包不符均保持 PID 空白。配对用于防止意外错配；JSON 不含数字签名，能够同时修改 PCAP 和元数据的人可以重新计算摘要，系统没有声称提供抗恶意伪造的认证。

可过滤字段包括 labproc.pid、labproc.name、labproc.status、labproc.session、labproc.original_number、labproc.sample_ns、labproc.associated_ns、labproc.created、labproc.local。回环连接的两个本机端点都可能产生 owner，同一个 PID 可能出现多次；按 PID 筛选可获得该进程观察到的多条 TCP 流。

## Listener

labdemo_stats.lua 用 UDP 双向端点和请求编号配对；按包号去重，retap/reset 清空统计。报告请求、响应、配对数、错误、无效消息、重复请求、等待、超时和平均响应时间。错误魔数没有 labdemo 字段，不计入无效 LABDEMO 数。未知类型异常计为无效消息，其错误响应单独计数。超时以抓包内最后一个有效协议消息时间为参考；尾部没有后续消息时保持 pending。无配对时平均响应时间为 unknown。

TShark 加载 labdemo.lua 与 labdemo_stats.lua 后使用 -q，stdout 输出 LABDEMO_STATS。GUI 菜单位于“Statistics → UCAS → LABDEMO request response statistics”。最多处理原始帧号 100000 以内的消息，达到上限显示 limited=true。extcap 选做未实现。
