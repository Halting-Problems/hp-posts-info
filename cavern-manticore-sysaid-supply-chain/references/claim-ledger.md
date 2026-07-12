# Claim Ledger

| ID | Status | Claim | Sources |
| --- | --- | --- | --- |
| C1 | confirmed | Check Point Research explicitly states that SysAid was not compromised and no SysAid vulnerability was involved. After gaining access to victim environments, Cavern Manticore abused the legitimate SysAid software-update feature to deploy a WinDirStat DLL-sideloading package. WinDirStat.exe loaded a trojanized uxtheme.dll Cavern Agent, which loaded n-HTCommp.dll for command and control and operator-selected modules. CPR also observed initial footholds through existing RMM software in multiple intrusions. | https://research.checkpoint.com/2026/cavern-manticore-exposing-iran-linked-modular-c2-framework/ |
| C2 | unknown | Exact complete exposure window and all victim systems are not public. | Public sources reviewed |
