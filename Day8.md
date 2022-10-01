# [Day 8] 近代 fuzzer 始祖 - AFL - Fuzzer - 校正 & Fork server



由於所有處理的邏輯都寫在 function `fuzz_one()`，導致此 function 多達 1600 行，因此會拆成多個部分介紹，其中有些處理會包含機率，通常是以 if-else condition 如 `UR(100) < 99` (1% 的機率會發生) 的形式出現，不過有些行為摻雜機率只是為了增加隨機性，並不影響核心概念，因此會斟酌刪減程式碼，方便讀者閱讀。



### 開檔與校正

`fuzz_one()` 在一開始會對要執行的 input 做校正 (calibrate)，確保 input 本身沒有什麼問題：

```c
static u8 fuzz_one(char** argv)
{
    // 變數 "pending_favored" 儲存了走到新 coverage 的 input 個數，
    // 代表還有比較好的 seed 可以用來執行，因此先略過 "被 fuzz 過" 或
    // "非 favored" 的 seed
    if (pending_favored && (queue_cur->was_fuzzed || !queue_cur->favored))
		return 1;

    // 取出 queue entry 對應到的檔案內容，並且使用 memory 的方式存取
    fd = open(queue_cur->fname, O_RDONLY);
    len = queue_cur->len;
    orig_in = in_buf = mmap(0, len, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    close(fd);

   	// 如果過去有發生 calibrate 沒有成功的情況，在此會執行一次
    if (queue_cur->cal_failed) {
        res = calibrate_case(argv, queue_cur, in_buf, queue_cycle - 1, 0);
        // 如果發生錯誤，代表此 seed 有問題
        if (res == FAULT_ERROR)
            FATAL("Unable to execute target application");
    }
    ...
}
```



`calibrate_case()` 的功能一共有兩個： 1. 執行 target 建立 fork server、2. 測試新的 input 是否有問題。昨天有介紹在 `main()` 時會呼叫 `perform_dry_run()` 檢查程式是否存在明顯問題，一執行就出現異常，而背後就是呼叫 `calibrate_case()` 來檢測 input 的執行結果，並且同時也喚起 fork server。

`calibrate_case()` 的程式碼如下：

```c
static u8 calibrate_case(char** argv, struct queue_entry* q, u8* use_mem,
                         u32 handicap, u8 from_queue)
{
    // 如果 TUI 顯示在 calibration mode，就代表正在執行此 function
    stage_name = "calibration";

    // fork server 還沒被喚起，因此先初始化 fork server
    if (!forksrv_pid)
        init_forkserver(argv);

	// 校正次數預設為 8 次
    for (stage_cur = 0; stage_cur < 8; stage_cur++) {
		show_stats();
        // 將資料寫到檔案 "<output_dir>/.cur_input" 當中
        write_to_testcase(use_mem, q->len);
        // 執行 target binary
        fault = run_target(argv, use_tmout);
        
        // 如果初次執行 (!stage_cur) 就沒有任何 coverage (!count_bytes(trace_bits))，
        // 代表程式本身有問題
        if (!stage_cur && !count_bytes(trace_bits))
            goto abort_calibration;

        // 藉由 checksum 能迅速得知執行結果是否相同
        cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);
        
        // 如果同個 input 走到的 coverage 與第一次不相同
        if (q->exec_cksum != cksum) {
			// 變數 "virgin_bits" 紀錄執行到現在還沒走到的 coverage，
            // has_new_bits() 會回傳是否這次執行是否產生新的結果
            // return value == 1 代表只改變某 edge 走到的次數
            // return value == 2 代表有走到新的 edge
            hnb = has_new_bits(virgin_bits);
            if (hnb > new_bits) new_bits = hnb; // 只存最好的結果
					
            // 如果並非第一次執行，則會檢查過去第一次跟這次執行結果是否有差
            // 變數 "var_bytes" 會紀錄哪些 coverage 可能是包含隨機性，
            // 像是根據執行時間會有不同的結果，因此如果有差的話，
            // 則會將對應的位址設為 1，代表是 variable (多變的)
            if (q->exec_cksum) {
                for (u32 i = 0; i < MAP_SIZE; i++) {
                    if (!var_bytes[i] && first_trace[i] != trace_bits[i])
                        var_bytes[i] = 1;
                }
                var_detected = 1;
            } else {
                // 如果是第一次執行，儲存到 queue entry 的結構當中，
                // 並且將 bitmap 的結果存到變數 "first_trace"
                q->exec_cksum = cksum;
                memcpy(first_trace, trace_bits, MAP_SIZE);
            }
        }
    }
    
	// 蒐集 performace 相關的資料
    q->exec_us     = (stop_us - start_us) / 8; // 平均執行時間
    q->bitmap_size = count_bytes(trace_bits); // 走到的 coverage 大小
    q->cal_failed  = 0; // 標記成校正成功

    // 藉由統計資料產生分數，代表此 input 的價值
    // 如果第 i 個 edge 同時有兩個 queue entry 能走到，
    // 則變數 top_rated[i] 就會紀錄 "執行時間*檔案大小" 比較小的 entry
    update_bitmap_score(q);

abort_calibration:
    // 有走到新的 edge，並且過去沒有紀錄有新 coverage 過
    // 更新 q->has_new_cov 為 1，代表此 entry 會走到新的 edge
    if (new_bits == 2)
        q->has_new_cov = 1;

    // 標註此 entry 執行的 edge 具有隨機性
    if (var_detected)
        mark_as_variable(q);
        
    return fault;
}
```

雖然目前還不知道 function `run_target()` 的行為以及回傳值，不過可以猜測 function 本身在執行 target，而回傳值則是執行結果。



### 喚起 fork server

`init_forkserver()` 在 `main()` 初始化時會被間接呼叫到。首先會建立用於跟 child 溝通的 pipe，然後由 child 執行 target，再來就如同 Day6 所介紹，target 會先在插樁產生的程式碼中執行 fork server，並且等待 fuzzer 下指令。

`init_forkserver()` 的程式碼如下：

```c
void init_forkserver(char** argv)
{
    int st_pipe[2]; // status pipe
   	int ctl_pipe[2]; // control pipe

    // 建立 status pipe 與 control pipe
	pipe(st_pipe);
    pipe(ctl_pipe);
    forksrv_pid = fork();
    
    if (!forksrv_pid) { // child process
        // 將 stdout 與 stderr 導向 /dev/null，代表不接收任何輸出
        dup2(dev_null_fd, 1);
        dup2(dev_null_fd, 2);
        // 將 input file 導向 stdin，代表輸入資料為檔案內容
        dup2(out_fd, 0);

        dup2(ctl_pipe[0], 198); // 只留 control read
        dup2(st_pipe[1], 199); // 只留 status write

        // 執行 target binary
        execv(target_path, argv);
    }
	
    fsrv_ctl_fd = ctl_pipe[1]; // 只留 control write
    fsrv_st_fd  = st_pipe[0]; // 只留 status read

    // 等待來自 target 的 handshake
    // 如果能成功收到 4 bytes value，代表正常啟動
    rlen = read(fsrv_st_fd, &status, 4);
    if (rlen == 4)
        return;
    
    // error handle
    ...
}
```



現在已經知道 fuzzer 是在什麼時間點執行 target 來喚起 fork server，並且也知道了 fuzzer 是如何檢測初次執行的 input。再來會介紹校正 input 後的 fuzzer 會做什麼行為，並揭開校正時執行的 function `run_target()` 其神秘面紗。

