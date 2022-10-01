# [Day 24] OS fuzzer - kAFL 原始碼 - Patched QEMU & KVM



由於 kAFL 是透過 instruction `hypercall` 在 host 與 guest (VM) 之間交換資訊，因此需要新增客製化的 `hypercall` handler。並且蒐集 coverage 使用的是 Intel-PT，因此也需要在 hypervisor 內執行相關設定。因為這些緣故，所以 kAFL 對 QEMU 與 KVM 做了一些更動，目的就是要支援這些功能。接下來會介紹 kAFL 分別對 QEMU 與 KVM 做了哪些程式碼的更動，以及這些更動的目的為何。



### KVM-PT

KVM-PT 的檔案架構如下，有些檔案比較沒什麼特別的，像是 Makefile 就是新增一些編譯時的參數，這就不會額外說明：

```
.
├── arch
│   └── x86
│       ├── include
│       │   ├── asm
│       │   │   └── kvm_host.h.patch
│       │   └── uapi
│       │       └── asm
│       │           └── kvm.h.patch
│       └── kvm
│           ├── vmx.c.patch
│           ├── vmx.h
│           ├── vmx_pt.c
│           ├── vmx_pt.h
│           └── x86.c.patch
└── include
    └── uapi
        └── linux
            └── kvm.h.patch
```

- **新增檔案**
  - **vmx_pt.\*** - 由於 Intel-PT 要追蹤的是 VM 執行流程，所以需要更新 VMX (Intel-VX) 的相關暫存器，不過這部分大多需要參考手冊才能知道對應暫存器的功能
- **檔案更動**
  - **kvm_host.h.patch** - 為 kvm file operation 結構新增兩個 function pointer 成員，分別為 `setup_trace_fd` 與 `vmx_pt_enabled`
  - **x86.c.patch** - kAFL hypercall interface，當 VM 呼叫 `hypercall` 而 trap 到 KVM，會先到此處理請求與相關參數，像是更新代表失敗原因的結構成員 `exit_reason`
  - **kvm.h.patch** - 定義一些與 QEMU 共用的 macro



#### vmx_pt.c

vmx_pt.c 程式碼分為四個部分：

- **Userspace interface** - userspace 的程式可以透過 `ioctl` 設定 Intel-PT
- **Entry/exit** - 處理進 VM 跟從 VM 出來時，需要對 Intel-PT 的設定做調整
- **Setup** - 建置 Intel-PT 的設定環境
- **Initialization** - 建置環境時會需要初始化一些設定值

接下來用於介紹的程式碼都已經刪除了相較不重要的部分，有興趣的讀者在參考原本內容。首先先看 userspace interface 的程式碼：

```c
// 對 vmx-pt fd 呼叫 ioctl 時會執行 vmx_pt_ioctl()
static struct file_operations vmx_pt_fops = {
    .unlocked_ioctl = vmx_pt_ioctl, 
};

static long vmx_pt_ioctl(..., unsigned int ioctl, ...)
{
    // 根據 ioctl 參數做不同的處理
    switch (ioctl) {
        // 設定、開啟、關閉特定範圍的 Intel-PT 追蹤
        case KVM_VMX_PT_{CONFIGURE,ENABLE,DISABLE}_ADDR{0...3}: ...
        // 設定、開啟、關閉特定 CR3 的追蹤
        case KVM_VMX_PT_{CONFIGURE,ENABLE,DISABLE}_CR3: ...
        // 開啟、關閉 Intel-PT
        case KVM_VMX_PT_{ENABLE,DISABLE}: ...
    }
}

int vmx_pt_create_fd(...){
    // 回傳 "vmx-pt" 類別的 fd，並使用 vmx_pt_fops 作為 function table
    // 此 function 能透過 KVM request 呼叫
    if (enabled){
        return anon_inode_getfd("vmx-pt", &vmx_pt_fops, ...); 
    }
}
```

Entry/exit 的處理：

```c
void vmx_pt_vmentry(struct vcpu_vmx_pt *vmx_pt){
    // 進到 VM 前，將 Intel-PT 的設定寫入對應的 msr 當中
    vmx_pt_reconfigure_cpu(vmx_pt);
}

void vmx_pt_vmexit(struct vcpu_vmx_pt *vmx_pt){
    // 從 rtit msr 讀 topa 並存入 vmx_pt 結構
    // topa 為 table of physical address
   	// rtit 為 real time instruction trace
    rdmsrl(MSR_IA32_RTIT_OUTPUT_BASE, topa_base);
    rdmsrl(MSR_IA32_RTIT_OUTPUT_MASK_PTRS, topa_mask_ptrs);
    WRITE_ONCE(vmx_pt->ia32_rtit_output_base, topa_base);
    WRITE_ONCE(vmx_pt->ia32_rtit_output_mask_ptrs, topa_mask_ptrs);
}
```

Setup 與 initialization 基本上就是設置一開始的 topa 以及 rtit msr，比較沒什麼特別的，在此就不贅述。



#### x86.c.patch

考慮到 markdown 不支援 patch syntax，接下來類似的檔案會都經過修改，以 C code 方式呈現：

```c
// 新增 ioctl 時傳入的 KVM 請求處理
case KVM_VMX_PT_SUPPORTED:
    r = kvm_x86_ops->vmx_pt_enabled();
case KVM_VMX_PT_SETUP_FD:
    r = kvm_x86_ops->setup_trace_fd(vcpu);

// 用 rax 是否存放 magic number 來判斷是否為
// VM 透過 hypercall 發送給 KVM 的請求
if (kvm_register_read(vcpu, VCPU_REGS_RAX) == HYPERCALL_KAFL_RAX_ID){
    switch(kvm_register_read(vcpu, VCPU_REGS_RBX)){
        // 各個請求值對應的 exit_reason 其意義 self-explanatory
        case 0:
            // 會將請求值與相關狀態儲存到 exit_reason 成員，
            // 此成員會在 QEMU-PT 使用到
            vcpu->run->exit_reason = KVM_EXIT_KAFL_ACQUIRE;
        case 1 ... 13: ...;
    }
}
```



### QEMU-PT

不考慮 QEMU monitor (hmp) 的更動，QEMU-PT 的目錄結構如下：

```
.
├── include
│   └── qom
│       └── cpu.h.patch
├── kvm-all.c.patch
├── linux-headers
│   └── linux
│       └── kvm.h.patch
├── pt
│   ├── decoder.{c,h}
│   ├── disassembler.{c,h}
│   ├── filter.{c,h}
│   ├── hypercall.{c,h}
│   ├── interface.{c,h}
│   ├── khash.h
│   ├── logger.{c,h}
│   ├── memory_access.{c,h}
│   └── tnt_cache.{c,h}
├── pt.{c,h}
└── vl.c.patch
```

- **新增檔案**
  - **pt/** - 與解析 Intel-PT packet 相關
    - **hypercall.c** - 定義 hypercall handler
    - **interface.c** - 註冊 QEMU device object 與一些客製化屬性，這些屬性能透過 command option 傳入。同時也會初始化 object member，像是 bitmap memory
  - **pt.c** - 與呼叫 KVM 執行 Intel-PT 相關
- **檔案更動**
  - **cpu.h.patch** - 在 QEMU 的 virtual CPU 結構中新增與 tracing 相關的結構
  - **kvm.h.patch** - 與 KVM 共用的 macro
  - **vl.c.patch** - vl.c 存放 QEMU main function `qemu_init()`，而 patch 會額外做一些 Intel-PT 相關的初始化
  - **kvm-all.c.patch** - 新增 KVM `exit_reason` handler，也就是像 `KVM_EXIT_KAFL_ACQUIRE` 的 hypercall 請求



#### kvm-all.c.patch

根據 KVM 回傳的 `exit_reason` 執行 hypercall handler，function name 的格式為 `handle_hypercall_XXX`：

```c
switch (exit_reason) {
    case KVM_EXIT_KAFL_ACQUIRE:
        handle_hypercall_kafl_acquire(run, cpu);
    case ...; handle_hypercall_...();
}
```



#### pt/hypercall.c

以 request `KVM_EXIT_KAFL_ACQUIRE` 來說，會交由 `handle_hypercall_kafl_acquire()` 來處理，初始化 QEMU 中 Intel-PT 相關資訊：

```c
void handle_hypercall_kafl_acquire(...) {
    // 如果還沒初始化
    if (!init_state){
		// 初始化 filter，也就是追蹤的範圍
        init_det_filter();
        // 開啟 PT
        pt_enable(cpu, false);
        cpu->pt_enabled = true;
    }
}
```



#### pt.c

以解析 packet 來更新 bitmap 來說，pt.c 定義了 function `pt_enable_ip_filtering()` 註冊指定 IP 範圍使用的 decoder function `pt_bitmap`：

```c
int pt_enable_ip_filtering(CPUState *cpu, uint8_t addrn, uint64_t ip_a, uint64_t ip_b, bool hmp_mode){
    // 指定追蹤範圍
    cpu->pt_ip_filter_a[addrn] = ip_a;
    cpu->pt_ip_filter_b[addrn] = ip_b;
    // 透過 ioctl KVM 設定 Intel-PT
    r += pt_cmd(cpu, KVM_VMX_PT_CONFIGURE_ADDR0+addrn, hmp_mode);
    r += pt_cmd(cpu, KVM_VMX_PT_ENABLE_ADDR0+addrn, hmp_mode);
    // 註冊 decoder 結構，並且 decode function 為 pt_bitmap
    cpu->pt_decoder_state[addrn] = pt_decoder_init(buf, ip_a, ip_b, &pt_bitmap);
}

// kAFL 紀錄 bitmap 分成 vertex 與 edge：
// vertex 用來存某個 basic block 走到的次數
// edge 就是 path
static void pt_bitmap(uint64_t addr){
    // 更新 vertex bitmap
    hypercall_submit_address(addr);
    // transition 即是 AFL 中的 edge value
    transition_value = (addr ^ (last_ip >> 1)) & 0xffffff;
    // 紀錄當前 edge value 總共產生的次數
    hypercall_submit_transition(transition_value);
    // 更新 edge bitmap
    bitmap[transition_value & (kafl_bitmap_size-1)]++;
    last_ip = addr;
}
```

Function `trace_disassembler()` 存在於 pt/disassembler.c，用來解析 Intel-PT packet，而在過成中會呼叫 `self->handler()`，實際上會執行到 `pt_bitmap()`：

```c
bool trace_disassembler(...){
    // obj 為每個封包結構，彼此會用 linked list 串起來
    obj = get_obj(self, entry_point, tnt_cache_state);
    while(true) {
        // cofi：Change of Flow Instruction
        switch(obj->cofi->type) {
			// conditional branch
            case COFI_TYPE_CONDITIONAL_BRANCH:
                // 取得 taken or non-taken 資訊
                tnt = process_tnt_cache(tnt_cache_state);
                switch(tnt) {
                    case TAKEN:
                        // 呼叫 handler 也就是 pt_bitmap() 來更新 bitmap
                        self->handler(obj->cofi->ins_addr);
                        obj = get_obj(self, obj->cofi->target_addr, tnt_cache_state);
                        break;
                    case NOT_TAKEN: ...;
                }
                break;
        }
    }
}
```



---

因為架構相較複雜，如果對 QEMU 或是 KVM 不太熟的讀者，在研究這些程式碼時建議與 workflow 的架構圖一起看，能更清楚了解每個 component 之間是怎麼運作的。

新增 hypercall handle 執行 VM 的請求固然簡單明瞭，但是只要 QEMU 或是 KVM 一改版，patch 就必須重更新一次，這也減少了便利性，同時因為 QEMU-PT 負責通知 KVM 開啟 Intel-PT，因此紀錄相關資訊與解析 packet 的操作都必須整合到 QEMU 內，這個部分也是比較不直觀的地方。

明天會介紹 kAFL-fuzzer 目錄底下的檔案，包含 loader、agent 與 fuzzer 的實作細節，像是 instruction `hypercall` 到底長什麼樣子、loader 是怎麼傳送 hypercall 給 fuzzer、範例 agent 會做什麼事情、fuzzer 是如何產 payload 的等等。

