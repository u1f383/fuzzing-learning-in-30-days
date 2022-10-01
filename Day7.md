# [Day 7] 近代 fuzzer 始祖 - AFL - Fuzzer - 初始化 & Fuzzing loop



前幾天已經介紹 afl 在編譯時會對 target 做怎樣的處理，並且了解 fuzzing 時 target 是如何與 fuzzer 做互動。接下來要講 afl fuzzer 本身的行為，包含初始化環境、做 mutation、分析 coverage、產生下個 input 等等，由於 afl-fuzz 的原始碼 afl-fuzz.c 行數高達八千多行，不可能將每個部分的細節都說明的很清楚，因此請有興趣者在自己追追看。

下方介紹皆以 Day4 執行 fuzzer 時使用的指令為例：

```bash
~/AFL/afl-fuzz -i in -o out ./test
```



### 支援參數

在 `main()` 的一開始 afl-fuzz 就會處理使用者傳入的參數，較重要的 options 有：

- -i - 存放 test case 的資料夾
- -o - 存放執行結果資料夾
- -f - 從指定檔案讀 input
- -t - timeout，執行時間超過的話會被 kill 掉
- -m - memory limit，執行時所能使用記憶體上限
- -d - skip deterministic，也就是 mutation 階段跳過預設的處理
- -n - 對沒有插樁的 target 做 fuzzing



### 初始化

處理完傳入的參數後，會初始化 fuzzing 時的環境，呼叫的 function 以及其行為可以參考註解，後續對於重要的 function 會在拿出來講：

```c
int main(int argc, char** argv)
{
    // 除了註冊收到終止請求的 signal 時會執行的 handler，因為介面是 TUI，
	// 因此也會註冊關於調整 window 大小的 signal。
    // handler 一共分成 stop, timeout, resize, skip
    setup_signal_handlers();
    // 保存執行指令，也就是 "/home/user/AFL/afl-fuzz -i in -o out ./test"
    save_cmdline(argc, argv);
    // 透過 /proc/sys/kernel/core_pattern 調整 dump 形式
    // 確保不會額外執行其他 program
    check_crash_handling();
    // 預設 CPU 會動態根據執行狀況來分配 frequency，可能會有其他影響，因此改成 performance
    // performance - Run the CPU at the maximum frequency
    check_cpu_governor();
    // 設置與 target 共享的 shared memory，
    // 在 fuzzer 中對應的變數為 "trace_bits"，
    // 也代表該次執行的 coverage 會存在此變數當中
    setup_shm();
    // 建立 output 資料夾
    setup_dirs_fds();
    // 從 input 資料夾取得 test case 並加到 queue 當中
    // 每個 seed file 對應到一個 queue entry
    // 指向第一個 entry 的變數為 "queue_top"
    read_testcases();
    // 為所有 queue entry 對應的檔案建立一個 hardlink
    pivot_inputs();
    // 預設 fuzzer 會餵 input 到 target 的 stdin
    // 這邊可以設置將 input 以檔案的形式傳給 target
    // 將參數名稱設為 @@ 即可
    detect_file_args(argv + optind + 1);
    // 建立指定 "<output_dir>/.cur_input" 作為目前 fuzzing 的 input file
    // fd 對應到的變數名稱為 "out_fd"
    setup_stdio_file();
    // 檢查 target binary 有無插樁
    check_binary(argv[optind]);
	// 將所有 seed 作為 input 執行 target
    // 確保程式原本的 seed 不會讓程式一執行就出現異常
    use_argv = argv + optind;
    perform_dry_run(use_argv);
    // 印出初始化的 TUI 統計畫面，準備開始 fuzzing
    show_init_stats();
    ...
}
```



### Fuzzing Loop

當環境初始化後，就會進入 fuzzing 無窮迴圈：

```c
while (1) {
    // 選出在 queue 當中 "favor" 的 entry，
    // 並標示其他 entry 為 "redundant"
    cull_queue();
    
    // 如果目前已經將 queue entry 都執行過一次，
    // 則進入下一個 queue cycle
    if (!queue_cur)
    {
        queue_cycle++;
        queue_cur = queue;

        // 變數 seek_to 紀錄下一個 cycle 需要 skip 的 entry 數量
        while (seek_to) {
            seek_to--;
            queue_cur = queue_cur->next;
        }
        // 印出 TUI 畫面
        show_stats();
        // 這次 queue entry 的數量跟上個 cycle 相同，
        // 就會在 mutation 時使用 splicing
        if (queued_paths == prev_queued) {
            use_splicing = 1;
        }
        
        prev_queued = queued_paths;
    }

   	// 執行一次 fuzzing
    fuzz_one(use_argv);
    // 如果執行過程中，fuzzer 本身出現狀況，或是 target 有奇怪的問題，
    // 就會跳出 while loop 停止 fuzzing
    if (stop_soon) break;
    
    // 取得下一個 queue entry 來執行
    queue_cur = queue_cur->next;
}
```

到此就是 afl-fuzz.c 的 `main()` 所做的行為，再來會需要關心 `fuzz_one()` 是怎麼將當前的 queue entry，從取得檔案內容餵入 target binary，到對 content 做 mutation，最後判斷執行結果好壞。






