# [Day 28] OS fuzzer - syzkaller - syz-fuzzer & syz-executor



昨天介紹 syz-manager 建立了 VM pool 來復現漏洞或是 fuzzing，但實際上是用 RPC (remote procedure call) 呼叫 syz-fuzzer 做 fuzzing，因此 fuzzing 邏輯與處理都是由 syz-fuzzer 實作。接下來就會介紹 syz-fuzzer 怎麼實作其他 OS fuzzer 難以模仿的 mutation 機制，也就是產生出 "有意義的 syscall sequence"，並且這些 syscall sequence 又是怎麼傳給 syz-executor 執行。



### syz-fuzzer

syz-fuzzer 的原始碼檔案為 syz-fuzzer/fuzzer.go，內容如下：

```go
func main() {
    // 這裡指的 target 就是 syz-manager 透過 RegisterTarget() 的
	target, err := prog.GetTarget(*flagOS, *flagArch)
    // 儲存 syz-manager 要檢查的成員
	checkArgs := &checkArgs{
		target:         target,
        ...
	}
    // 與 manager 建立連線
	manager, err := rpctype.NewRPCClient(*flagManager, timeouts.Scale)
    // a 與 r 分別為呼叫 RPC 時用來傳遞參數與接收結果的變數
    a := &rpctype.ConnectArgs{...}
	r := &rpctype.ConnectRes{}
    // 呼叫 RPC "Manager.Connect"，與 manager 建立連線
	manager.Call("Manager.Connect", a, r)
    checkArgs.gitRevision = r.GitRevision
	// ... 儲存到結構當中
    r.CheckResult, err = checkMachine(checkArgs)
    // 呼叫 RPF "Manager.Check"，載入 corpus
	manager.Call("Manager.Check", r.CheckResult, nil)
	fuzzer := &Fuzzer{
		name:                     *flagName,
		...
	}
	
    for needCandidates, more := true, true; more; needCandidates = false {
        // 等待 input candidate
		more = fuzzer.poll(needCandidates, nil)
	}
    // 紀錄哪些 syscall 才能執行
    calls := make(map[*prog.Syscall]bool)
	for _, id := range r.CheckResult.EnabledCalls[sandbox] {
		calls[target.Syscalls[id]] = true
	}
    // choice table 記錄了被允許的 syscall，
    // 在後續 mutate 時會略過這些 syscall
	fuzzer.choiceTable = target.BuildChoiceTable(fuzzer.corpus, calls)
    // 執行數個 syz-executor 開始 fuzzing
	for pid := 0; pid < *flagProcs; pid++ {
		proc, err := newProc(fuzzer, pid)
		fuzzer.procs = append(fuzzer.procs, proc)
		go proc.loop()
	}
	fuzzer.pollLoop()
}
```

- Fuzzer 的 `poll()` 實際上是向 manager 發送 RPC 來呼叫 `Manager.Poll`，取得 input candidate
  - Candidate 的定義為從 corpus 取出且沒做過 "triaged" 的 input，triaged 會在後續介紹，可以先視 candidate 為初始 input
  - 透過 RPC 呼叫的 function 會定義在 syz-manager/rpc.go，在呼叫 syz-manager 的 function 來處理

而原本的 thread 會呼叫 `fuzzer.pollLoop()`，更新一些執行資訊而已，不是很重要，因此接下來會看 `proc.loop()` 做了哪些處理，原始碼位於 syz-fuzzer/proc.go：

```go
func (proc *Proc) loop() {
	for i := 0; ; i++ {
		item := proc.fuzzer.workQueue.dequeue()
        // 執行哪個 handler 取決於 workqueue 內存放的 item 是什麼型態，
        // 這些操作都是針對當前的 program
		if item != nil {
			switch item := item.(type) {
			case *WorkTriage:
				proc.triageInput(item)
			case *WorkCandidate:
				proc.execute(proc.execOpts, item.p, item.flags, StatCandidate)
			case *WorkSmash:
				proc.smashInput(item)
			}
			continue
		}

		ct := proc.fuzzer.choiceTable
		fuzzerSnapshot := proc.fuzzer.snapshot()
        // 沒有其他 input，或是到達一定週期時滿足 if-condition
		if len(fuzzerSnapshot.corpus) == 0 || i%generatePeriod == 0 {
            // 建立一個新的 program，可以看到傳入 choice table 給 generator
			p := proc.fuzzer.target.Generate(proc.rnd, prog.RecommendedCalls, ct)
			proc.executeAndCollide(proc.execOpts, p, ProgNormal, StatGenerate)
		} else {
            // 對現有的 program 做 mutate，也傳了 choice table 給 mutator
			p := fuzzerSnapshot.chooseProgram(proc.rnd).Clone()
			p.Mutate(proc.rnd, prog.RecommendedCalls, ct, fuzzerSnapshot.corpus)
			proc.executeAndCollide(proc.execOpts, p, ProgNormal, StatFuzz)
		}
	}
}
```

在此介紹 syzkaller 與 program 相關的處理：

- **Generation** - 產生 syscall sequences 與參數
- **Mutation** - 對 program 的參數或是 syscall sequence 做隨機的變化，像是改變資料，或是新增新的 syscall
- **Triage** - 在 program 產生新的 coverage 時執行，可以再拆成兩個部分：
  - **Verification** - 認證 coverage 是可以被重現的
  - **Minimization** - 保持 coverage 的情況下移除多餘的 syscall，並且縮短必要的參數
- **Smash** - 對新的 seed 做 100 次的 mutation

雖然執行很多操作，不過這裡不會一一介紹，只會以執行 syz-executor 的 `proc.execute()` 與做 mutation 的 `p.Mutate()` 為目標。

---

首先先看 `proc.execute()`，基本上是一層層的 wrapper function，因此已經大量刪除了比較不重要的程式碼：

```go
func (proc *Proc) execute(execOpts *ipc.ExecOpts, p *prog.Prog, ...) ... {
	info := proc.executeRaw(execOpts, p, ...)
}

func (proc *Proc) executeRaw(opts *ipc.ExecOpts, p *prog.Prog...) ... {
    // 檢查 disabled syscall
	proc.fuzzer.checkDisabledCalls(p)
    // 載入 program
	proc.logProgram(opts, p)
    // 這邊會執行 syz-executor
    output, info, hanged, err := proc.env.Exec(opts, p)
}
```

`proc.env.Exec()` 會執行傳入的 program `p`，並回傳執行資訊給 syz-fuzzer。

---

`p.Mutate()` 一共會執行五種 mutation 操作，分別為：

- **squashAny** - 替換有結構性的參數，換成是隨機 binary blob (binary large object)
- **splice** - 拼接參數
- **intertCall** - 在隨機位置插入一個 syscall
- **mutateArg** - 對隨機一個 syscall 參數做 mutate
- **removeCall** - 隨機移除一個 syscall

```go
func (p *Prog) Mutate(rs rand.Source, ncalls int, ct *ChoiceTable, corpus []*Prog) {
    // ...
	for stop, ok := false, false; !stop; stop = ok && len(p.Calls) != 0 && r.oneOf(3) {
		switch {
		case r.oneOf(5):
			ok = ctx.squashAny()
		case r.nOutOf(1, 100):
			ok = ctx.splice()
		case r.nOutOf(20, 31):
			ok = ctx.insertCall()
		case r.nOutOf(10, 11):
			ok = ctx.mutateArg()
		default:
			ok = ctx.removeCall()
		}
	}
}
```

拿比較簡單的操作 `insertCall()` 為例，在 program 中隨機位置插入一個 syscall 的程式碼如下：

```go
func (ctx *mutator) insertCall() bool {
	p, r := ctx.p, ctx.r
    // 產生隨機位址
	idx := r.biasedRand(len(p.Calls)+1, 5)
	// ...
    // 產生 syscall
	calls := r.generateCall(s, p, idx)
    // 插入 syscall
	p.insertBefore(c, calls)
}
```

想得簡單一點，就是在一個 list 當中隨機選個位置，並將 element 塞到這個位置前面，list 就是整個 syscall sequence，而 element 就是新產生的 syscall。



### syz-executor

Syzkaller 用一種特別的資料結構來儲存 program，並且各個 component 之間都用此結構來傳遞 program，這種結構能將 program 序列化成類似 C function call 的形式：

```
r0 = open(&(0x7f0000000000)="./file0", 0x3, 0x9)
read(r0, &(0x7f0000000000), 42)
close(r0)
```

最後 program 傳給 syz-executor 後，syz-executor 內部會將 program parse 成 syscall 的形式來呼叫。

syz-executor 的原始碼路徑為 executor/executor.cc，是用 C++ 來撰寫的程式，但實際上大多還是寫 C，只是一些 algorithm 的處理用 C++ library 比較好處理。除了執行 syscall 之外，syz-executor 本身還支援多個功能，不過這次介紹以 `exec`，也就是執行 syscall sequence 為主，並且不考慮其他 define，原始碼如下：

```cpp
int main(int argc, char** argv)
{
    // 功能用第一個參數判斷 (argv[1])
	if (argc == 2 && strcmp(argv[1], "version") == 0) {...}
	// 下方為 "exec" 邏輯

    // 類似於 AFL 的 control pipe
	setup_control_pipes();
    // 接收 exeuctable
	receive_execute();
	if (flag_coverage) {
        // 每個 thread coverage 的初始化，包含設置 KCOV
		// ...
        cover_open(&extra_cov, true);
        // mmap kcov fd
		cover_mmap(&extra_cov);
	}
    // 
    status = do_sandbox_none();
    // 回傳 execute_reply 結構
	reply_execute(status);
	return status;
}
```

接收 program 會先讀一些 input 資訊，像是長度、magic number，而後才會接收 program 資料：

```cpp
void receive_execute()
{
	execute_req& req = last_execute_req;
    // 接收 execute request 並檢查是否合法
	if (read(kInPipeFd, &req, sizeof(req)) != (ssize_t)sizeof(req))
		fail("control pipe read failed");
	if (req.magic != kInMagic)
		failmsg("bad execute request magic", "magic=0x%llx", req.magic);
	if (req.prog_size > kMaxInput)
		failmsg("bad execute prog size", "size=0x%llx", req.prog_size);
    // 處理 request flags
	parse_env_flags(req.env_flags);
    // 將 flag value 存到變數當中
	flag_collect_signal = req.exec_flags & (1 << 0);
	// ...

    // 接收 program 直到給定大小 (req.prog_size)
	uint64 pos = 0;
	for (;;) {
		ssize_t rv = read(kInPipeFd, input_data + pos, sizeof(input_data) - pos);
		pos += rv;
		if (rv == 0 || pos >= req.prog_size)
			break;
	}
}
```

呼叫執行 program 的 wrapper function `do_sandbox_none()`：

```c
static int do_sandbox_none(void)
{
	unshare(CLONE_NEWPID);
	int pid = fork();
    // parent 進 loop 等待 child process 得離開
	if (pid != 0)
		return wait_for_loop(pid);
    
    // setup fuse
	setup_common();
    // 與 parent 區隔執行環境
	sandbox_common();
    unshare(CLONE_NEWNET);
    // 降低程式的部分權限，避免有 hang 住的情況
	drop_caps();
    // 初始化網路設備 (optional)
    // ...
    initialize_netdevices_init();
    
	loop();
	doexit(1);
}
```

根據不同的模式，`loop()` 有不同的 define，以下為正常情況：

```c
static void loop(void)
{
	execute_one();
}
```

`execute_one()` 會解析整個 program 並執行，其中也包含開啟 KCOV、參數設置等等處理：

```c
void execute_one()
{
    // input_data 即是在 receive_execute() 所接收的 program
	uint64* input_pos = (uint64*)input_data;
    
    // 允許 KCOV 追蹤 coverage，不過執行前還是會重置
    cover_enable(&threads[0].cov, flag_comparisons, false);
    
	for (;;) {
        // call_num 可以想成是 bytecode instruction
		uint64 call_num = read_input(&input_pos);
		if (call_num == instr_eof) break; // 結束
        // 複製參數
		if (call_num == instr_copyin) {
			char* addr = (char*)read_input(&input_pos);
			uint64 typ = read_input(&input_pos);
			switch (typ) {
			// 參數的種類
			case arg_const: ...
			case arg_result: ...
			case arg_data: ...
			case arg_csum: ... // checksum handle
				uint64 size = read_input(&input_pos);
				uint64 csum_kind = read_input(&input_pos);
				switch (csum_kind) {
				case arg_csum_inet: ...
                }
			}
			continue;
		}
		if (call_num == instr_copyout) {...}
		if (call_num == instr_setprops) {...}
        
        // 接下來就是 syscall 的呼叫
		const call_t* call = &syscalls[call_num];
        // 檢查 syscall 是否能執行
		if (call->attrs.disabled) error();
        // 參數數量
		uint64 num_args = read_input(&input_pos);
		uint64 args[kMaxArgs] = {};
        // 讀參數
		for (uint64 i = 0; i < num_args; i++)
			args[i] = read_arg(&input_pos);
        // 將剩下參數初始為 0
		for (uint64 i = num_args; i < kMaxArgs; i++)
			args[i] = 0;
        
        // 分配給 worker thread，但先不執行
		thread_t* th = schedule_call(call_index++, call_num, copyout_index,
					     num_args, args, input_pos, call_props);
		// 執行 syscall
        execute_call(th);
        // 處理並傳送執行結果
        handle_completion(th);
	}
}
```

終於來到最後一個 function，`execute_call()` 首先重置 KCOV 確保乾淨，接著執行 syscall，最後儲存該次執行產生的 coverage 個數，等著待會分析：

```c
void execute_call(thread_t* th)
{
	const call_t* call = &syscalls[th->call_num];
	// 重置 KCOV
    cover_reset(&th->cov);
    // 執行 syscall
	NONFAILING(th->res = execute_syscall(call, th->args));
    // 蒐集該次執行的 coverage
	if (flag_coverage)
		cover_collect(&th->cov);
}
```

到這邊，已經將 syzkaller 的整個架構與大概的執行流程說明一次，並且為了瞭解細節，對於各個 component 也對原始碼做完善的分析。



## OS fuzzer 總結

OS fuzzer 是一個很值得研究的主題，雖然 syzkaller 很萬用，但在一些 kernel subsystem 的處理上可能就有滿大的優化空間，像是 filesystem 的 fuzzing，最理想的情況是能夠將機制整合到 syzkaller 當中，這樣也能讓 syzbot 持續的跑並自動回報。

不論是 userspace fuzzer 或是 kernel fuzzer，現在對讀者來說應該很熟悉了，接下來兩天會介紹兩個截然不同的 hypervisor fuzzer，分別為 Nyx 與 Hypercube，只需要再兩天，就已經可以說把目前 fuzzing 領域所使用的大部分技巧、優化與實作方式都學習的差不多了。

