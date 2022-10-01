# [Day 27] OS fuzzer - syzkaller - syzlang & syz-manager



今天會簡單介紹 syzlang 的格式與撰寫方法，並透過原始碼來了解 syz-manager 如何初始化執行環境與管理系統。



### syzlang

syzkaller 自定義了一種語言 syzlang 來描述 syscall 的格式，像是 syscall number、參數、回傳型態等等，[官方文件](https://github.com/google/syzkaller/blob/master/docs/syscall_descriptions.md)已經說明的很詳細，在這邊就轉成中文懶人包。

首先，直接拿現成的檔案 sys/linux/sys.txt 來參考，在檔案的開頭有一些 kernel header file，這只是表示裡面使用到的一些 const 或是 define 的值是來自哪些檔案，而實際上 syzkaller 在解析完 kernel header file 後會存到檔案 sys.txt.const，可以隨便加上 `include <hello/world>` 並編譯來觀察，實際上編譯後不會壞掉，因為 syzlang parser 根本不看這個部分：

```
include <linux/socket.h>
include <linux/ptrace.h>
include <linux/resource.h>
include <linux/stat.h>
...
include <hello/world>
```

而解析 header file 所產生檔案 sys.txt.const 為下，就是一些 macro 展開的值或是 const value：

```
ADDR_COMPAT_LAYOUT = 2097152
ADDR_LIMIT_32BIT = 8388608
ADDR_LIMIT_3GB = 134217728
ADDR_NO_RANDOMIZE = 262144
ADJ_ESTERROR = 8
...
```

再來則是一些 type define 像是 `alignptr`、`align32` 與 `align64`，接收另一個 type `T` 並自動 alignment 到特定 bytes：

```
type alignptr[T] {
	v	T
} [align[PTR_SIZE]]

type align32[T] {
	v	T
} [align[4]]

type align64[T] {
	v	T
} [align[8]]
```

Type define 的語法類似於 C 的 `typedef`，而 `[0:65]` 代表只會產生 0~65 此型態的值：

```
type signalno int32[0:65]
type signalnoptr intptr[0:65]
...
```

再來是定義 syscall format，下列包含 `open()` 與 `openat()` 與一些結構、定值。`$dir` 則是代表特定的 `open()` 格式的名字為 `dir`，`sock_fprog` 定義新的結構，`open_flags` 則是定義 value set。參數的話下方會以 `open()` 做介紹：

```
open(file ptr[in, filename], flags flags[open_flags], mode flags[open_mode]) fd
open$dir(file ptr[in, filename], flags flags[open_flags], mode flags[open_mode]) fd_dir

openat$dir(...) fd_dir
openat(...) fd

sock_fprog {
	len	len[filter, int16]
	filter	ptr[in, array[sock_filter]]
}

open_flags = O_WRONLY, O_RDWR, O_APPEND, FASYNC, O_CLOEXEC, O_CREAT, O_DIRECT, O_DIRECTORY, O_EXCL, O_LARGEFILE, O_NOATIME, O_NOCTTY, O_NOFOLLOW, O_NONBLOCK, O_PATH, O_SYNC, O_TRUNC, __O_TMPFILE
```

- `file`、`flags` 與 `mode` 都是參數的名字，`fd` 則是回傳值的名稱
- `in` 與 `out` 用來定義資源順序，`in` 代表寫資料進去，`out` 代表輸出的結果
- `ptr`、`flags` 則是參數型態，雖然 self-explanatory，不過細節可以參考[文件](https://github.com/google/syzkaller/blob/master/docs/syscall_descriptions_syntax.md#syscall-description-language)說明
  - `ptr` - 指向 object (`filename`) 的指標，可以額外給一些 option 定義指標屬性
  - `flags` - 一些數值的集合，以此為例就是 `open_flags`，mutate 時就會從中選一或多個作為 `flags` 參數
- `filename` 為 `string` 的特例，能在執行時產生合法的檔案名稱

在 sys.txt.const 下方的位置定義了各個 syscall 在不同指令集的 number：

```
__NR_acct = 51, amd64:163, arm64:riscv64:89, mips64le:5158
__NR_alarm = 27, amd64:37, arm:arm64:riscv64:???, mips64le:5037
__NR_brk = 45, amd64:12, arm64:riscv64:214, mips64le:5012
...
```

---

除了 sys.txt 之外，sys/linux/ 底下也有許多 \*.txt 檔，sys.txt 定義了比較多通用的 syscall 格式，而其他 .txt 檔則是定義與 subsystem 溝通的 syscall，舉例來說 bpf.txt 定義與 linux ebpf system 互動的 syscall。

而當修改完這些檔案後，可以執行下列命令做更新：

```bash
bin/syz-sysgen
```

實際上 syz-sysgen 就是 syzlang 的 parser，在讀完這些 "source code" 之後，就會產生 "output file"，而 "output file" 即是 sys/linux/gen/amd64.go，不同指令集與作業系統的格式為 `sys/$OS/gen/$INSN.go`。下列為 amd64.go 的部分內容，能清楚知道 syzlang parser，也就是 syz-sysgen 做了什麼事情：

```golang
package gen

import . "github.com/google/syzkaller/prog"
import . "github.com/google/syzkaller/sys/linux"

// RegisterTarget() 會向 fuzzer 註冊 linux amd64 的 syscall 格式、規則以及常數
func init() {
    RegisterTarget(&Target{OS: "linux", Arch: "amd64", Revision: revision_amd64, PtrSize: 8, PageSize: 4096, NumPages: 4096, DataOffset: 536870912, LittleEndian: true, ExecutorUsesShmem: true, Syscalls: syscalls_amd64, Resources: resources_amd64, Consts: consts_amd64}, types_amd64, InitTarget)
}

// resource，像是 value 範圍
var resources_amd64 = []*ResourceDesc{
    {Name:"ANYRES16",Kind:[]string{"ANYRES16"},Values:[]uint64{18446744073709551615,0}},
    {Name:"ANYRES32",Kind:[]string{"ANYRES32"},Values:[]uint64{18446744073709551615,0}},
    {Name:"ANYRES64",Kind:[]string{"ANYRES64"},Values:[]uint64{18446744073709551615,0}},
    {Name:"ANYRES8",Kind:[]string{"ANYRES8"},Values:[]uint64{18446744073709551615,0}},
    {Name:"IMG_DEV_VIRTADDR",Kind:[]string{"IMG_DEV_VIRTADDR"},Values:[]uint64{0}},
    ...
}

// syscall，包含 number 以及傳入的參數
var syscalls_amd64 = []*Syscall{
    {NR:43,Name:"accept",CallName:"accept",Args:[]Field{
        {Name:"fd",Type:Ref(11387)},
        {Name:"peer",Type:Ref(10173)},
        {Name:"peerlen",Type:Ref(10453)},
    },Ret:Ref(11387)},
    {NR:43,Name:"accept$alg",CallName:"accept",Args:[]Field{
        {Name:"fd",Type:Ref(11390)},
        {Name:"peer",Type:Ref(5022)},
        {Name:"peerlen",Type:Ref(5022)},
    },Ret:Ref(11391)},
    ...
}

// consts，也就是常數
var consts_amd64 = []ConstValue{
    {"ABS_CNT",64},
    {"ABS_MAX",63},
    {"ACL_EXECUTE",1},
    ...
}
```

透過 function `RegisterTarget()` 即可跟 fuzzer 註冊使用者定義的 syscall 格式。



### syz-manager

syz-manager 也是整個 syzkaller 系統的進入點，以下為程式碼 syz-manager/manager.go：

```go
func RunManager(cfg *mgrconfig.Config) {
	// 建立 VM
    vmPool, err = vm.Create(cfg, *flagDebug)
    // ... 目錄相關的處理
    
    // 初始化各 sub component，名字就 self-explanatory
	reporter, err := report.NewReporter(cfg)
	mgr := &Manager{...}
	mgr.preloadCorpus()
	mgr.initStats()
	mgr.initHTTP()
	mgr.collectUsedFiles()
	mgr.serv, err = startRPCServer(mgr)
    mgr.dash, err = dashapi.New(cfg.DashboardClient, cfg.DashboardAddr, cfg.DashboardKey)

    // 每 10 秒在 terminal 印出執行狀況
	go func() {
		for lastTime := time.Now(); ; {
			time.Sleep(10 * time.Second)
            // ... 一些統計資料
			corpusCover := mgr.stats.corpusCover.get()
			log.Logf(0, "VMs %v, executed %v, cover %v, ...", numFuzzing, executed, corpusCover, ...)
		}
	}()
    // 定期更新 dashboard 的 thread
    go mgr.dashboardReporter()
    // 喚起 VM
	mgr.vmLoop()
}
```

Function `vmLoop()` 不斷等待 VM 的執行結果並執行對應的處理：

```go
func (mgr *Manager) vmLoop() {
    // 計算最多可以有幾個 VM instance 復現 (reproduce) 漏洞發生
    instancesPerRepro := 4 // 多少 VM 來 repro
    vmCount := mgr.vmPool.Count() // total
    // 每隔 10 秒建立一個 VM instances
    instances := SequentialResourcePool(vmCount, 10*time.Second*mgr.cfg.Timeouts.Scale)

    for shutdown != nil {
        // 將要被 repro 的 crash 加到 queue 當中
        for crash := range pendingRepro {
            reproducing[crash.Title] = true
            reproQueue = append(reproQueue, crash)
        }

        // 取出最後一個 repro 並 assign 給 VM
        for canRepro() {
            vmIndexes := instances.Take(instancesPerRepro)
            crash := reproQueue[ len(reproQueue) - 1 ]
            go func() {
                reproDone <- mgr.runRepro(crash, vmIndexes, instances.Put)
            }()
        }
        // 運行沒有事情的 VM instance
        for !canRepro() {
            idx := instances.TakeOne()
            go func() {
                crash, err := mgr.runInstance(*idx)
                runDone <- &RunResult{*idx, crash, err}
            }()
        }

        // 處理 VM 的執行狀況
        wait:
        select {
            case <-instances.Freed: // VM 被釋放
            case stopRequest <- true: // VM 停止執行
            case res := <-runDone: // VM 執行結束
            case res := <-reproDone: // VM 復現 crash
            case <-shutdown: // syzkaller system shutdown
            ...
        }
    }
}
```

For loop 的邏輯非常簡單，需要注意的是 VM instance 呼叫的 function 會因為使用的 hypervisor 不同而不同，舉例來講檔案 vm/qemu/qemu.go 就定義了以 QEMU 為 hypervisor 時，呼叫 `inst.boot()` 或是 `inst.Copy()` 底部的實作方法。再來往前看當初建立 VM pool 時 `vm.create()` 是怎麼處理的：

```go
func Create(cfg *mgrconfig.Config, debug bool) (*Pool, error) {
	typ, ok := vmimpl.Types[cfg.Type]
    // cfg 為 config，即為使用者定義的資料，像是目標 OS 與指令集
	env := &vmimpl.Env{
		Name:     cfg.Name,
		OS:       cfg.TargetOS,
		Arch:     cfg.TargetVMArch,
		Workdir:  cfg.Workdir,
		Image:    cfg.Image,
		SSHKey:   cfg.SSHKey,
		SSHUser:  cfg.SSHUser,
		Timeouts: cfg.Timeouts,
		Debug:    debug,
		Config:   cfg.VM,
	}
	impl, err := typ.Ctor(env)
	return &Pool{
		impl:     impl,
		workdir:  env.Workdir,
		template: cfg.WorkdirTemplate,
		timeouts: cfg.Timeouts,
	}, nil
}
```

---

到此分析整個系統入口 syz-manager 做的事情，雖然範例程式碼刪除了細節處理的部分，但是整個概念非常清楚。此外也介紹了 syzlang 的語法與輸出結果，但雖然可以知道 `RegisterTarget()` 向 fuzzer 註冊一個 linux amd target，但 fuzzer 會怎麼利用他，又怎麼以此來產生 syscall sequence，就留著明天介紹。

