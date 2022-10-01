# [Day 6] 近代 fuzzer 始祖 - AFL - 插樁程式碼



在 Day 4, 5 已經了解 afl 是如何包裝編譯的過程，並且在組譯時插入程式碼，在此做個小結論：

- afl-gcc 包裝了 gcc 的執行參數來 compile 原始碼
- afl-as 包裝了 as 的執行參數，插樁在 compile 出來的 asm file，而插樁的位置大致涵蓋所有 basic block 以及 **main function 的開頭**
- 最後 as 組譯 asm file 產生執行檔

今天會介紹插了哪些程式碼，以及這些程式碼是怎麼跟 fuzzer 做互動。



### 插樁程式碼

在 afl-as.c 的 function `add_instrumentation()` 中對會對每個 basic block 做插樁，內容包含變數 `main_payload_64` 與 `trampoline_fmt_64`，而這兩個變數定義在 afl-as.h，不過 `main_payload_64` 主要是定義 afl 相關的 function，因此先看 `trampoline_fmt_64` 就好：

```c
static const u8* trampoline_fmt_64 =
    // 更新 stack (1)
    "leaq -(128+24)(%%rsp), %%rsp\n"
    // 保存 register value (2)
    "movq %%rdx,  0(%%rsp)\n"
    "movq %%rcx,  8(%%rsp)\n"
    "movq %%rax, 16(%%rsp)\n"
    "movq $0x%08x, %%rcx\n" // (5)
    
    // 呼叫 afl function (3)
    "call __afl_maybe_log\n"

    // 恢復 register value 以及更新 stack (4)
    "movq 16(%%rsp), %%rax\n"
    "movq  8(%%rsp), %%rcx\n"
    "movq  0(%%rsp), %%rdx\n"
    "leaq (128+24)(%%rsp), %%rsp\n";
```

為了避免影響到目前的執行流程，因此要先建立新的 stack frame (1)，並保存執行期間會使用到的 register (2)，而後呼叫處理 coverage 的 afl function `__afl_maybe_log()` (3)，最後恢復 register 與 stack (4)。在插樁過程中，會隨機產生一組代表當前 basic block 的 id (5)，透過 RCX 傳入 `__afl_maybe_log()`，待會就能知道這組 id 有什麼功能。

因為對於每個 basic block 都會執行這段 asm code，因此執行效率會與 native 的有差，並且當 input 所覆蓋的 coverage 越高，執行速度就越慢。

---



`__afl_maybe_log()` 定義在變數 `main_payload_64` 當中，用來初始化 fuzzing 環境以及蒐集 coverage。因為 asm 不好看出程式邏輯，因此用下方的 C pseudo code 來介紹：

```c
// 與 fuzzer 溝通用的 pipe (1)
#define READ_PIPE_FD 198
#define WRITE_PIPE_FD 199

char _afl_maybe_log(__int64 a1, __int64 a2, __int64 a3, __int64 bbid)
{
    // 是否需要初始化 (2)
    if ( !_afl_area_ptr )
    {
        // 取得 shared memory (3)
        shmid_str = getenv("__AFL_SHM_ID");
        shmid_int = atoi(shmid_str);
        shm = shmat(shmid_int, NULL, 0);
        _afl_area_ptr = shm;

        // handshake (4)
        if ( write(WRITE_PIPE_FD, &_afl_temp, 4) == 4 )
        {
// --------------- fork server (5) ---------------
            while ( 1 )
            {
                if ( read(READ_PIPE_FD, &_afl_temp, 4) != 4 ) // (6)
                    break;
                pid = fork();
                if ( !pid )
                    goto __afl_fork_resume;
                
                write(WRITE_PIPE_FD, &pid, 4);
                waitpid(pid, &_afl_temp, 0); // (7)
                write(WRITE_PIPE_FD, &_afl_temp, 4);
            }
            _exit(0);
        }
    }
__afl_fork_resume: // (8)
    // 蒐集 coverage
    edge = _afl_prev_loc ^ bbid;
    _afl_prev_loc = (_afl_prev_loc ^ edge) >> 1;
	++*(_afl_area_ptr + edge);
}
```

Target 由 fuzzer 透過 `fork()` 與 `execve()` 執行，而 fuzzer 在執行 target 前會建立一組 pipe (fd 為 198, 199)，這樣兩者就能透過讀寫 pipe 來做溝通 (1)。



在 `main()` 會第一次呼叫 `__afl_maybe_log()` 並做初始化，而 function 本身是透過全域變數 `_afl_area_ptr` 來判斷是否為第一次執行 (2)。一開始會先取得 fuzzer 建立的 shared memory address (3)，用來蒐集目標在執行時的 coverage。再來會與 fuzzer 做 handshake (4) 來確保 fuzzer 存活，類似於 TCP 的三項交握。確定能夠與 fuzzer 的溝通後準備要開始 fuzzing，在 (5) 之後的行為會被稱作 **fork server**，行為如下：

- 等待 fuzzer 發出指令 (6)
- `fork()` 出一個 child process
  - child process 會繼續執行後續的程式碼 (8)
  - parent process 會等待 child process 的結束 (7)，並在結束後告知 fuzzer
- child 在之後呼叫 `_afl_maybe_log()` 只會執行 (8) 之後的行為



而 (8) 之後做的就是在**蒐集 coverage**。實際上 AFL 紀錄 coverage 時是以 **edge** 為單位，而 edge 是由兩個 basic block 所組成。舉個簡單的例子：

```
A --> B
B --> A
```

如果是以 basic block 為單位，則兩者對於 B coverage 的定義只在於有沒有執行到，因此 coverage 相同；但以 edge 為單位，(A, B) 與 (B, A) 會被分別視為兩個不同執行單位，因此會產生出不同的 coverage，這樣的好處在於 coverage 本身能考慮到上下文，而不是只考慮執行多少程式碼。



AFL 將當前 basic block id (變數 `bbid`) 與前一次的 basic block id 做運算，取得 edge value 後記錄在 shared memory 當中。當 child 執行結束，parent 會從 `waitpid()` 離開 (7)，並通知 fuzzer 這次執行已經結束，而 fuzzer 就能透過 shared memory 的紀錄來分析這次執行的效果。


