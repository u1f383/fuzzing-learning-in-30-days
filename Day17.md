# [Day 17] 優化找 coverage 的能力 - 符號執行 Symbolic execution & 實際運用的困難



程式當中充斥許多 if-else condition，這些條件判斷使得程式在不同的情況下有不同的處理方式，而每個 condition 都是將各個變數的比較做組合。如果將這些 condition 轉換成數學式子，則會發現有許多共通之處，像是靜態期間變數的值無從得知，就對應到數學當中的未知數；大於、等於與小於的比較在數學中也有相同的行為，因此科學家嘗試用**符號**表示**變數**，"模擬"變數的值來執行程式，藉此通過特定路徑，獲得輸出結果，而這樣的處理也被稱作**符號執行 (symbolic execution)**。

概念就是把程式的變數視為符號，並且把走到特定 function 的路徑上所有 if-else 條件組合起來，解出各個符號的值需要在什麼範圍當中，最後產生對應的 input 來滿足這些條件，不過具體數學是如何計算，以及解這些條件限制 (constraint) 時使用什麼演算法，這方面我不是很熟，因此這篇文章會著重在介紹實際應用。

目前常看見使用到 symbolic execution 的工具有 [z3](https://github.com/Z3Prover/z3)、[angr](https://github.com/angr/angr) (底層使用 Claripy solver)，關於這兩個工具的使用可以參考 2016 HITCON 演講 [Binary 自動分析的那些事](https://hitcon.org/2016/CMT/slide/day1-r1-a-1.pdf) 的投影片，內容詳細之外還附上使用方法。在此介紹的是 [S2E](https://github.com/S2E/s2e) (**S**ymbolic **E**xecution **E**ngine)，一個提供符號執行與程式分析的平台。

**S2E** 提供了一步到位的 interface，除了初始化複雜的環境只需要下一些命令之外，對程式中的資料解 symbolic 也只需要呼叫一些 library API，連 VM 的執行都能夠幫你做到。

S2E 底層使用了 KVM 與 QEMU，讓使用者可以在 VM 當中執行，並免污染到主機環境，同時 S2E 也使用了 `LD_PRELOAD` 載入 S2E 的 library：libs2e.so，藉此在 QEMU 開始執行之前做 S2E 的環境初始化，並且讓 QEMU 能呼叫到 S2E 的 function，而接下來會介紹這個成熟的 symbolic execution engine 是如何包裝與實作。



---

S2E 的環境建置稍微複雜一點，要安裝的東西也比較多，請參考以下命令：

```bash
### (~500M)
# 安裝 dependencies
sudo apt install git gcc python3 python3-dev python3-venv
# 先安裝 s2e 的 python environment
git clone https://github.com/S2E/s2e-env.git
cd s2e-env
python3 -m venv venv
. venv/bin/activate
pip install .

### (~20G)
# 建立存放相關執行檔的目錄
mkdir ~/s2e_build && cd ~/s2e_build
# 初始化，會安裝一大堆 dependencies (347M)
s2e init .
. ./s2e_activate
# 編譯
s2e build
# 產生 ubuntu-22.04-x86_64 VM image
s2e image_build ubuntu-22.04-x86_64
```

參考官方文件 [tutorial](https://s2e.systems/docs/Tutorials/BasicLinuxSymbex/SourceCode.html) 的 **Introduction** & **Compiling and running**，在指定目錄編譯測試執行檔 (下方以 /home/user/s2e_build/tests 為指定目錄)，並且執行下方命令，在 /home/user/s2e_build/projects/tutorial1 底下建立相關檔案：

```bash
s2e new_project ./tutorial1
```

測試執行結果：

```bash
cd /home/user/s2e_build/projects/tutorial1 && ./launch-s2e.sh
# 或者是
s2e run tutorial1
```

最後在 projects/tutorial1 目錄底下會有 `s2e-out-` 前綴的資料夾，裡面存放執行結果。

---



在初始化環境，並確保可以執行後，再來要修改 tutorial1.c 的程式碼，讓 S2E 知道哪些資料是要被 symbolic。

方法雖然有很多種，但最直接的方式就是在程式碼中指定變數為 symbolic，S2E 提供了 API `s2e_make_symbolic()` 做到這件事情。原先在程式當中會等待使用者輸入字串，在此呼叫 `s2e_make_symbolic()` 來模擬使用者輸入，傳入 `(symbol 位址, symbol 大小, symbol 名稱)`，S2E 就會將位址填入 symbol value 做分析。在程式的最後呼叫 `s2e_get_example()` 取得執行結果：

```c
/** 原本的資料來源為使用者輸入
printf("Enter two characters: ");
if (!fgets(str, sizeof(str), stdin)) {
	return 1;
}**/
s2e_make_symbolic(str, 2, "str");
str[3] = 0;

if (str[0] == '\n' || str[1] == '\n') {
    // ...
} else {
    // ...
}

s2e_get_example(str, 2);
printf("'%c%c' %02x %02x\n", str[0], str[1], (unsigned char) str[0], (unsigned char) str[1]);
```

這邊把更新過的 tutorial1.c 重新命名為 tutorial2.c 以方便區隔，並且因為使用到 S2E library，因此先前編譯的命令需要更新：

```bash
gcc -I/home/user/s2e_build/source/s2e/guest/common/include -O3 tutorial2.c -o tutorial2
```

---



S2E function `s2e_make_symbolic()` 實際上會插入一段有格式的非法 instruction，透過 objdump 執行檔 tutorial2，能看到 `s2e_make_symbolic()` 產生的 instruction 如下：

```
1107:       0f 3f                   (bad)
1109:       00 03                   add    BYTE PTR [rbx],al
110b:       00 00                   add    BYTE PTR [rax],al
110d:       00 00                   add    BYTE PTR [rax],al
110f:       00 00                   add    BYTE PTR [rax],al
```

當 CPU 執行到非法 instruction 時會送 SIGILL，代表 CPU 看不懂，而 S2E library 則是透過 SIGILL 來攔截 VM 的執行，並且根據種類做對應的操作，instruction 的種類可以看 s2e_build/source/s2e/guest/common/include/s2e/opcodes.h：

```c
#define BASE_S2E_CHECK          0x00
#define BASE_S2E_MAKE_SYMBOLIC  0x03
#define BASE_S2E_IS_SYMBOLIC    0x04
...
```

對照 objdump 的結果，能知道 0f 3f 為 S2E 產生的非法 instruction，00 03 則是代表種類為 `BASE_S2E_MAKE_SYMBOLIC`。

再來會透過原始碼介紹 S2E library 是從哪邊接收到 `BASE_S2E_MAKE_SYMBOLIC`，這部分相較複雜，可以斟酌查看：

```c
// ========== libs2eplugins/src/s2e/Plugins/Core/BaseInstructions.cpp ==========
// handleBuiltInOps() 有一個 switch case 負責處理各種 s2e opcode
void BaseInstructions::handleBuiltInOps(..., uint64_t opcode) {
    switch ((opcode >> 8) & 0xFF) {
        // 對於在程式中呼叫的 function s2e_make_symbolic() 做處理
        case BASE_S2E_MAKE_SYMBOLIC: {
            makeSymbolic(state);
        }
    }
}

// onCustomInstruction() 為 wrapper function，包了一層 range 的檢查
void BaseInstructions::onCustomInstruction(..., uint64_t opcode) {
    uint8_t opc = (opcode >> 8) & 0xFF;
    if (opc <= BASE_S2E_MAX_OPCODE) {
        handleBuiltInOps(state, opcode);
    }
}

void BaseInstructions::initialize() {
    // onCustomInstruction 的呼叫與 onCustomInstruction member 綁在一起
    s2e()->getCorePlugin()->onCustomInstruction.connect(sigc::mem_fun(*this, &BaseInstructions::onCustomInstruction));
}

// ========== libs2ecore/include/s2e/CorePlugin.h ==========
// 而 CorePlugin 的 member "onCustomInstruction" 實際上會註冊
// 在 guest 中執行到特定 opcode 時的會發出的 signal
sigc::signal<void, S2EExecutionState*, uint64_t> onCustomInstruction;

// ========== libs2ecore/src/CorePluginInterface.cpp ==========
void s2e_tcg_custom_instruction_handler(uint64_t arg) {
    try {
        // 在 tcg 中註冊客製 instruction 的處理
        // 也就是 tcg 執行到非法 opcode 0f 3f 時就會轉給上面註冊的 handler 來處理
        g_s2e->getCorePlugin()->onCustomInstruction.emit(g_s2e_state, arg);
    }
}

// ========== libs2ecore/src/S2EExecutor.cpp ==========
// 註冊對應名稱的 helper function
void s2e_initialize_execution(int execute_always_klee) {
    // "s2e_tcg_custom_instruction_handler" --> s2e_tcg_custom_instruction_handler()
    tcg_register_helper((void *) &s2e_tcg_custom_instruction_handler, "s2e_tcg_custom_instruction_handler", 1, sizeof(uint64_t));
}

// ========== libs2ecore/src/CorePluginInterface.cpp ==========
// tcg 讓程式去執行 s2e_tcg_custom_instruction_handler()
void s2e_tcg_emit_custom_instruction(uint64_t arg) {
    tcg_gen_callN((void *) s2e_tcg_custom_instruction_handler, nullptr, 1, args);
}

// ========== libs2e/src/s2e-libcpu-interface.cpp ==========
// 為 interface 註冊 function handler
void init_s2e_libcpu_interface(struct se_libcpu_interface_t *sqi) {
    sqi->events.tcg_emit_custom_instruction = s2e_tcg_emit_custom_instruction;
}

// ========== libs2e/src/s2e-kvm.cpp ==========
// 初始化 event handler
void S2EKVM::init(void) {
    init_s2e_libcpu_interface(&g_sqi);
}

// 建立 S2EKVM object 並做初始化
IFilePtr S2EKVM::create() {
    auto ret = std::shared_ptr<S2EKVM>(new S2EKVM());
    ret->init();
    s_s2e_kvm = ret;
    return ret;
}

// 在呼叫原本的 open64 前，會先執行此 function 來建立 KVM object
// 最後呼叫 g_original_open() 執行原本的 open64 syscall
int open64(const char *pathname, int flags, ...) {
    if (!strcmp(pathname, "/dev/kvm")) {
        // 建立
        kvm = s2e::kvm::S2EKVM::create();
    }
    g_original_open = (open_t) dlsym(RTLD_NEXT, "open");
    return g_original_open(pathname, flags, mode);
}
```

當 QEMU 送 KVM request `KVM_CREATE_VM` 時代表建立 VM，一樣會先在 S2E 做處理，最後才會呼叫到原本的 syscall，而這條路也會執行到 `s2e_initialize_execution()`，註冊 helper function：

```c
// ========== libs2ecore/src/S2EExecutor.cpp ==========
std::shared_ptr<VM> VM::create(std::shared_ptr<S2EKVM> &kvm) {
    auto ret = std::shared_ptr<VM>(new VM(kvm));
    s2e_initialize_execution(false);
}

// ========== libs2e/src/s2e-kvm.cpp ==========
// 建立 VM
int S2EKVM::createVM() {
    auto vm = VM::create(kvm);
}

// 為各種 kvm request 執行對應 s2e handler
int S2EKVM::sys_ioctl(int fd, int request, uint64_t arg1) {
    switch ((uint32_t) request) {
        case KVM_CREATE_VM: {
            // 如果 KVM ioctl 的 request 是要建立 VM，
            // 那對應的 s2e 環境也會需要建 VM
            ret = createVM();
        }
    }
}

// 在呼叫原本的 ioctl 前，會先執行此 function 來初始化 s2e 的環境
// 最後呼叫 g_original_ioctl() 執行原本的 ioctl syscall
int ioctl(int fd, int request, uint64_t arg1) {
    // 呼叫 S2EKVM::sys_ioctl()
	g_fdm->get(fd)->sys_ioctl(fd, request, arg1);
    g_original_ioctl = (ioctl_t) dlsym(RTLD_NEXT, "ioctl");
    return g_original_ioctl(fd, request, arg1);
}
```

---



總結來說，QEMU 在呼叫 KVM 前會先被 S2E 給攔截，S2E 會根據 request 的內容執行對應的 handler，像是建立 S2E VM。之後 QEMU 會透過 KVM 載入 linux kernel，並執行使用者所撰寫的程式 (i.e. tutorial1, tutorial2)，當執行到程式當中 0f 3f 此種非法 instruction 時，會呼叫 S2E 的 handler，並且根據 instruction 的種類做不同的處理，像是對某塊記憶體建立 symbolic。而後 S2E 不斷 fork 當前執行狀態來模擬輸入與解 constraint，如果條件可以解，則 S2E 最終會產生一或多組滿足這些條件的輸入，藉此走到特定路徑。



### 實際運用的困難

雖然符號執行 (symbolic execution) 與污點分析 (taint analysis) 的搭配能讓 fuzzer 走到更難走到的地方，但實際運用時卻很容易造成大量的 overhead。

以 symbolic execution 來說，執行過程中的 condition 越多，代表要處理的數學運算也越多，意即造成的 overhead 越大，然而迴圈在每次迭代時都會進行一次條件判斷，程式當中又免不了迴圈的處理，因此造成只要程式規模一大，使用迴圈的次數增加，就會導致 symbolic execution 的 overhead 增加，此狀況也稱作 **path explosion**。

而 taint analysis 也會遇到相同的問題，只要程式規模變大，要做的 propagation 就變多，間接造成的 overhead 也越高。

考慮到上述的情況，這兩個機制被整合到 fuzzer 前都需要在時間與品質中取得平衡，這也產生了另一個新實作機制：**Concolic execution**。Concolic execution 透過 symbolic execution 解一部份的條件，得到較大的 input 範圍，剩下的就透過隨機產生的 input 來嘗試。不過目前也不只有 concolic execution 能夠取得平衡，這部分也有許多研究正在進行。

