# 第三方组件与来源

本项目使用独立安装的 Npcap、Python 和 Wireshark，不在 ZIP 中重新分发它们的安装包。依赖通过固定版本 requirements 文件安装。许可证信息以对应发行包原文为准。

| 组件 | 实测版本 | 作者/项目与用途 | 许可 |
| --- | --- | --- | --- |
| Python | 3.12.14 | Python Software Foundation；运行环境 | PSF |
| PySide6-Essentials / shiboken6 | 6.12.0 | The Qt Company；Qt GUI 与绑定 | LGPLv3/GPLv3/商业许可，依发行组件 |
| Npcap | 1.90 | Nmap Project；Windows 抓包驱动 | Npcap License，独立安装 |
| Scapy | 2.8.0 | Scapy 项目；PCAP 文件读写和测试样本 | GPL-2.0-only |
| Lark | 1.3.1 | Erez Shinan 与贡献者；过滤语言 | MIT |
| psutil | 7.2.2 | Giampaolo Rodola 与贡献者；进程身份查询 | BSD-3-Clause |
| pefile | 2024.8.26 | Ero Carrera 与贡献者；DLL PE 位数检查 | MIT |
| pytest | 9.2.0 | pytest 开发者；真实执行验证 | MIT |
| pypdf | 7.1.0 | pypdf 开发者；课件文本与 PDF 校验 | BSD-3-Clause |
| ReportLab | 5.1.0 | ReportLab；实验报告 PDF | BSD |
| Wireshark/TShark | 4.6.9 | Wireshark Foundation 与贡献者；Lua 与交叉验证 | GPL-2.0-or-later |
| dkjson | 2.11 | David Heiko Kolf；Lua JSON 读取 | MIT，源码保留原文 |
| sha2.lua | v12，2022-02-23 | Egor Skriptunoff；Lua SHA256 | MIT，源码保留原文 |

vendor/dkjson.lua 来自作者发布的 https://dkolf.de/dkjson-lua/dkjson-2.11.lua ，SHA256 为 197cb50834c642f84b4cf99fe724932c50e6d9c92faec7ad89aa25e91df4d481。

vendor/sha2.lua 来自 https://raw.githubusercontent.com/Egor-Skriptunoff/pure_lua_SHA/master/sha2.lua ，SHA256 为 62d2e0885931a1f14db87e61cb3d74936bb5b1e19eb2b4994ab04c03d78f9ed6。实际文件位于 wireshark/vendor。作者版权声明和原始说明均保留。

Npcap API 使用 https://npcap.com/guide/wpcap/ 与 https://npcap.com/guide/npcap-devguide.html 的官方手册核对，结合 libpcap pcap.h、bpf.h 的 Windows 声明和本机 DLL 实际行为校验。Windows IP Helper API 使用 Microsoft Learn 的 GetExtendedTcpTable、MIB_TCPROW_OWNER_PID、MIB_TCP6ROW_OWNER_PID 文档核对。Lua API 使用 https://www.wireshark.org/docs/wsdg_html_chunked/wsluarm_modules.html 及 Wireshark 4.6.9 源码核对；实际适用版本以本项目验收记录为准。

项目实现与依赖边界：Scapy 没有参与实时字段解析和 TCP 重组；Lark 负责语法树构建，匹配语义由项目代码执行；Windows API 提供连接表，PID 时间关联由项目代码执行；Lua JSON 与摘要算法调用第三方实现。不得将这些依赖代码描述为学生原创算法。
