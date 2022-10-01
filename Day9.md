# [Day 9] 近代 fuzzer 始祖 - AFL - Fuzzer - Trimming & Mutation



今天主要會介紹 trimming 以及 mutation，並了解 function `run_target()` 的執行過程，而 `run_target()` 其實是用來通知 fork server 執行 target 的重要 function。



### 執行 target

Function `run_target()` 在多個檔案中都有定義 (afl-fuzz.c, afl-analyze.c ...)，不過在 afl-fuzz 使用的是 afl-fuzz.c 當中的 `run_target()`，因此如果讀者在自己追 code 時請注意不要看錯地方。

`run_target()` 會傳遞指令給 fork server 執行 target，並且等待執行結束，再來用結束的狀態來判斷是否發生異常，最後回傳狀態結果，程式碼如下：

```c
static u8 run_target(char** argv, u32 timeout)
{
	// 初始化紀錄 coverage 的 memory
    memset(trace_bits, 0, MAP_SIZE);
    MEM_BARRIER();

    // 發送指令給 fork server，而 fork server 在收到指令後會
    // fork 一個 child 來執行原本的程式邏輯
	write(fsrv_ctl_fd, &prev_timed_out, 4);
	read(fsrv_st_fd, &child_pid, 4);

    // 設置 timer，如果 timeout 就會收到 SIGALRM，
    it.it_value.tv_sec = (timeout / 1000);
    it.it_value.tv_usec = (timeout % 1000) * 1000;
    setitimer(ITIMER_REAL, &it, NULL);
	
    // 等待執行結束
	read(fsrv_st_fd, &status, 4));
    
    // 分類各個 edge 走到的次數，簡單化運算操作
    // 0 -> class1, ..., 3 -> class4, 4~7 -> class5, ...
    // 同個 class 的 edge 數會被設為相同，
    // 舉例來說分類到 class5 的 edge 次數都會被設為 8
    classify_counts((u64*)trace_bits);

    // 如果 target 是因為 signal 所終止，
    // 有可能就是觸發 segfault，或者是 ASAN 發現異常
    if (WIFSIGNALED(status)) {
        kill_signal = WTERMSIG(status);
        // 如果不是因為 timeout 而被 kill，就代表發生 crash
        if (child_timed_out && kill_signal == SIGKILL) return FAULT_TMOUT;
        return FAULT_CRASH;
    }

	// MSAN 發現異常
    if (uses_asan && WEXITSTATUS(status) == MSAN_ERROR) {
        kill_signal = 0;
        return FAULT_CRASH;
    }

    return FAULT_NONE;
}
```



### Trimming

`fuzz_one()` 在校正完 input 後，會準備開始執行 mutation，不過在此之前還會先將 input 做修剪 (trim)，刪除 input 當中不必要的部分：

```c
// 如果該 input 過去沒有做修剪
if (!queue_cur->trim_done) {
    u8 res = trim_case(argv, queue_cur, in_buf);
    queue_cur->trim_done = 1;
}

// 將修剪後的 input 複製到 <output_dir>/.cur_input 當中
memcpy(out_buf, in_buf, queue_cur->len);
```



Trimming 的目的為在不影響 coverage 的情況下，將 input 大小縮小以減少 overhead，舉例來說，如果 input "AAAABBBBCCCC" 與 "AAAACCCC" 所產生的 coverage 相同，則會將 "AAAABBBBCCCC" trim 成 "AAAACCCC"。

`trim_case()` 負責處理 trimming，程式碼如下：

```c
static u8 trim_case(char** argv, struct queue_entry* q, u8* in_buf)
{
	// 如果 input 本身資料就不多，則不需要刪減
    if (q->len < 5) return 0;
	
    // 求得 input len 的 pow of 2
    len_p2 = next_p2(q->len);

    // 移除的大小至少要為 4，也就是 trim 的最小單位
    // 而後以 input len 的 pow of 2 將 input 拆成 16 份，
    // 每份的長度則是 "remove_len"
    remove_len = MAX(len_p2 / 16, 4);
    
    while (remove_len >= MAX(len_p2 / 16, 4)) {
        // 初始的刪除位置為 "remove_len"
        u32 remove_pos = remove_len;
        
        while (remove_pos < q->len) {
            // 因為當初長度有做 pow of 2 ceiling，
            // 因此有可能最後一個部分的大小不足 "remove_len"
            u32 trim_avail = MIN(remove_len, q->len - remove_pos);
            u32 cksum;

            // 將 input 內容根據要刪除的位置與大小，將資料複製到
            // <output_dir>/.cur_input 對應到的 fd 當中
            write_with_gap(in_buf, q->len, remove_pos, trim_avail);
			
            // 執行 target 並取得 bitmap 的 checksum
            fault = run_target(argv, exec_tmout);
            cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);

            // 兩次的 coverage 相同，代表 input 可以做修剪
            if (cksum == q->exec_cksum) {
				// 變數 "move_tail" 計算出來後為後面沒有更新的資料的大小
                u32 move_tail = q->len - remove_pos - trim_avail;
                // 更新 input 內容與長度
                q->len -= trim_avail;
                // 將沒更新到的資料複製到前面，覆蓋掉已經被 trim 的資料
                memmove(in_buf + remove_pos, in_buf + remove_pos + trim_avail, 
                        move_tail);
                // 更新 pow of 2 長度
                len_p2  = next_p2(q->len);
                // 需要更新至檔案當中
                needs_write = 1;
            } else
                // 不相同的話則嘗試刪除下一個部分
                remove_pos += remove_len;
        }
        // 降低粒度，做更細緻的 trim
        remove_len >>= 1;
    }

	// 如果 input 已經被修剪，則同步至檔案當中
    if (needs_write) {
        s32 fd;
        unlink(q->fname);
        fd = open(q->fname, O_WRONLY | O_CREAT | O_EXCL, 0600);
        ck_write(fd, in_buf, q->len, q->fname);
        close(fd);
    }
    
    return fault;
}
```

`trim_case()` 的程式碼相較複雜，不過核心概念就是嘗試將 input 每固定長度刪除，如果 coverage 相同就可以將其移除，藉此減少 input 大小。



### Mutation

當 trimming 確保 input 只留下重要的部分後，會進入到 mutation stage，也就是反覆執行 "更新 input、執行 target、評估結果" 的循環。AFL 的 mutation strategy 會先讓新的 input 執行固定的變異，之後才會做真正隨機化的更新，因此又被稱作 **deterministic** step。

各變異的名稱與行為如下：

- bitflip1/1：一次翻 1 bit
- bitflip2/1：一次翻 2 bits
- bitflip4/1：一次翻 4 bits
- bitflip8/8：一次翻 1 byte
- bitflip16/8：一次翻 2 bytes
- bitflip32/8：一次翻 4 bytes
- Arith8/8：對每 byte 做 +-1, +-2, +-3, ..., +-35
- Arith16/8：對每 2 bytes 做 +-1, +-2, +-3, ..., +-35
- Arith32/8：對每 4 bytes 做 +-1, +-2, +-3, ..., +-35
- interest8/8：將某 byte 替換成 interest value 的值，而 interest value 是 edge case 的 value，如 MAX_INT、0
- interest16/8：將某 2bytes 替換成 interest value 的值
- interest32/8：將某 4bytes 替換成 interest value 的值

最後一組的變異是將隨機執行上述介紹的方法，因此很有可能產生差異很大的 input：

- havoc：會對 input 做許多次隨機 mutation



而因為變異很多，因此 `fuzz_one()` 的程式碼大部分都在處理 mutation，不過基本上概念大同小異，只需要知道其中一個怎麼做就好，以下為執行操作 "bitflip2/1" 的程式碼片段：

```c
// queued_path 為所有 queued testcases 的數量
// unique_crashes 為獨立的 crash 數量
new_hit_cnt = queued_paths + unique_crashes;
// stage 名稱
stage_name  = "bitflip 2/1";
// 每 2 bits 為一組，一共有幾組
stage_max   = (len << 3) - 1;
// 紀錄原先的 fuzzing 狀態 (testcases 數量 + crash 數量)
orig_hit_cnt = new_hit_cnt;

for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {
    // 翻過去
    FLIP_BIT(out_buf, stage_cur);
    FLIP_BIT(out_buf, stage_cur + 1);

    // 執行 target
	common_fuzz_stuff(argv, out_buf, len);

    // 翻回來
    FLIP_BIT(out_buf, stage_cur);
    FLIP_BIT(out_buf, stage_cur + 1);
}

// 更新在 bitflip 2/1 的過程中是否有新的 crash，
// 或是新增了新的 testcases
new_hit_cnt = queued_paths + unique_crashes;

// 更新此 stage 的成效 (new - old)
stage_finds[STAGE_FLIP2]  += new_hit_cnt - orig_hit_cnt;
```



mutation 的程式碼非常直觀且好懂，不過仍有些變異需要比較複雜的處理，在此就不多做說明，至於 `common_fuzz_stuff()` 是怎麼執行的，會在明天做介紹。

