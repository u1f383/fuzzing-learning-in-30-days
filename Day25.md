# [Day 25] OS fuzzer - kAFL 原始碼 - The fuzzer



再來介紹 kAFL 原始碼中最後一個 component： kAFL-fuzzer。kAFL 在 host 執行的部分基本上都是用 python 所撰寫，包含執行整個 kAFL、fuzzer 做 mutation、傳入 payload 等操作，好處是方便開發，而壞處則是效能不好，這又讓我再次懷疑他的實驗結果是否效能真的這麼好。



### kAFL-fuzzer

檔案結構如下：

```
.
├── agents
│   ├── kafl_user.h
│   └── linux_x86_64
│       ├── fuzzer/fs_fuzzer.c
│       └── loader/loader.c
├── common
│   ├── config.py
│   ├── debug.py
│   ├── evaluation.py
│   ├── qemu.py
│   ├── self_check.py
│   ├── ui.py
│   └── util.py
├── fuzzer
│   ├── communicator.py
│   ├── core.py
│   ├── process
│   │   ├── __init__.py
│   │   ├── mapserver.py
│   │   ├── master.py
│   │   ├── slave.py
│   │   └── update.py
│   ├── protocol.py
│   ├── state.py
│   ├── technique
│   │   ├── __init__.py
│   │   ├── ...
│   │   └── interesting_values.py
│   └── tree.py
└── kafl_fuzz.py
```

以 kafl_fuzz.py 的 `main()` 為整個 kAFL 的進入點，起初初始化執行環境，而後解析使用者自定義的設定檔，最後在 VM 中執行 agent 做 fuzzing。

整個過程中 component 之間彼此會使用各種機制來傳送資訊，像是共享一個 queue，每個 component 透過 queue element 就能得知資訊是否屬於他，此外 fuzzer 會用 socket 與 QEMU 做溝通，QEMU 也會用 shared memory 與 VM 做溝通。



#### agents/linux_x86_64

存放三個檔案，分別為：

- **fuzzer/fs_fuzzer.c** - 雖然名稱為 fuzzer，但實際上是 agent 的程式碼
- **loader/loader.c** - 接收 fuzzer 傳來的 agent 執行檔並執行
- **kafl_user.h** - 定義 hypercall 所執行的 instruction 為何，如何傳遞請求類型與參數

---

首先介紹 fs_fuzzer.c 的程式碼，其中部分的 hypercall 請求的功能已經由 macro 名稱解釋，就不額外寫註解：

```c
int main(int argc, char** argv)
{
    // 建立存放 payload 的記憶體區塊
    kAFL_payload* payload_buffer = mmap((void*)NULL, PAYLOAD_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	// setup
    // ...
    kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_CR3, 0);
    // 傳送 payload 位址給 fuzzer
    kAFL_hypercall(HYPERCALL_KAFL_GET_PAYLOAD, (uint64_t)payload_buffer);
	// KAFL_TMP_FILE 為存放 payload 的檔案
    backingfile = open(KAFL_TMP_FILE, O_RDWR | O_CREAT | O_SYNC, 0777);

    while(1) {
        // 請求 fuzzer 傳入 payload
        kAFL_hypercall(HYPERCALL_KAFL_NEXT_PAYLOAD, 0);
        // payload 寫入 payload file "backingfile"
        write(backingfile, payload_buffer->data, payload_buffer->size-4);
        
        // 通知 fuzzer 開始執行
        kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);
        // =========== syscall sequence ===========
        mount(loopname, "/tmp/a/", "ext4", payload_buffer->data[payload_buffer->size-4], NULL);
        mkdir("/tmp/a/trash", 0700);
        stat("/tmp/a/trash", &st);
        umount2("/tmp/a", MNT_FORCE);
        // ========================================
        // 該次執行結束，請求 fuzzer 處理這次 tracing 結果
        kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
    }
}
```

用來載入 agent 的 loader 的原始碼則是：

```c
static inline void load_programm(void* buf) {
    // 把 fuzzer 傳來的 program data 寫進檔案
    payload_file = open(TARGET_FILE, O_RDWR | O_CREAT | O_SYNC, 0777);
    write(payload_file, buf, PROGRAM_SIZE);
    close(payload_file);
    // 執行檔案
    payload_file = open(TARGET_FILE, O_RDONLY);
    fexecve(payload_file, newargv, newenviron);
}

int main(int argc, char** argv)
{
    program_buffer = mmap((void*)0xabcd0000, PROGRAM_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    // 與 fuzzer 做 handshake
    kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);
    kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
    // 傳給 fuzzer 要寫入 agent 的位址
    kAFL_hypercall(HYPERCALL_KAFL_GET_PROGRAM, (uint64_t)program_buffer);
    // 載入 agent
    load_programm(program_buffer);
}
```

kafl_user.h 定義了 function `kAFL_hypercall()`，內部實際上是執行 instruction `vmcall`，執行後會觸發 VM exit，並將 exit reason 儲存到對應的暫存器當中：

```c
// hypercall magic number
#define HYPERCALL_KAFL_RAX_ID			0x01f
#define HYPERCALL_KAFL_ACQUIRE			0
#define HYPERCALL_KAFL_GET_PAYLOAD		1
// ...
#define HYPERCALL_KAFL_NEXT_PAYLOAD		12

#define TARGET_FILE						"/tmp/fuzzing_engine"
#define TARGET_FILE_WIN					"fuzzing_engine.exe"	

typedef struct{
	int32_t size;
	uint8_t data[PAYLOAD_SIZE-4];
} kAFL_payload;

static inline void kAFL_hypercall(uint64_t rbx, uint64_t rcx){
	uint64_t rax = HYPERCALL_KAFL_RAX_ID;
    // rcx 放請求參數
	asm ("movq %0, %%rcx;" : : "r"(rcx));
    // rbx 放請求類型
	asm ("movq %0, %%rbx;" : : "r"(rbx));
    // rax 放 magic number
    asm ("movq %0, %%rax;" : : "r"(rax));
    asm ("vmcall");
}
```



#### common/

此目錄底下放的大多是與 fuzzer 機制無直接關係的程式碼，大概介紹一下各個檔案的行為，並挑出比較值得看的部分拿出來說明：

- **config.py** - 用來解析 config 檔
- **debug.py** - 定義 logger
- **evalutation.py** - 儲存執行的累積數據，像是 panic 數量
- **self_check.py** - 檢查 host 執行環境，像是是否安裝必要的 package、是否支援 Intel-VMX 等等
- **util.py** - 定義通用的 function
- **ui.py** - kAFL 使用者介面
- **qemu.py** - 比較重要的檔案，除了執行 QEMU 之外，同時也擔任 fuzzer 中負責與 QEMU 溝通的橋樑，像是傳送 payload、複製 bitmap



單純看 qemu.py 中 `class qemu` 的成員名稱與 function 名稱，就可以大概推敲出 qemu.py 負責處理 fuzzer 的哪些部分：
```python
class qemu:
    def __init__(self, qid, config):
        # ...
        self.bitmap_size = config.config_values['BITMAP_SHM_SIZE']
        self.config = config
        self.qemu_id = str(qid)

        # 各式各樣 kafl 的 predefined 檔案名稱
        self.payload_filename   = "/dev/shm/kafl_qemu_payload_" + self.qemu_id
		# ...
        self.cmd =  self.config.config_values['QEMU_KAFL_LOCATION'] + " " \
                    "-hdb " + self.config.argument_values['ram_file'] + " " \
                    # 一些 qemu command option，如果好奇加了哪些
        			# 可以直接去看沒有刪減的程式碼
        			# ...
                    ",bitmap=" + self.bitmap_filename
	
    	# 對 option 中的 ip property 做設定
        # ...
        self.cmd += " -loadvm " + self.config.argument_values["S"] + " "
        self.cmd += " -machine pc-i440fx-2.6 "

        # shared memory 與對應的 fd
        # 種類包含 bitmap, payload 等等
        self.kafl_shm_f = None
        self.kafl_shm   = None
        self.fs_shm_f   = None
        self.fs_shm     = None
        self.payload_shm_f   = None
        self.payload_shm     = None
        self.bitmap_shm_f   = None
        self.bitmap_shm     = None
        # 其他類型成員的初始化
        # ...
        # 將編譯後的 agent 透過 share memory 傳到 VM
        self.__set_binary(self.binary_filename,
                          self.config.argument_values['executable'], (16 << 20))
		
        # 執行 qemu，運行 VM
        def start(self, ...): ...
        # 設置 payload 到 shared memory
        def set_payload(self, ...): ...
        # 複製 bitmap
        def copy_bitmap(self, ...): ...
        # 接收從 QEMU 傳來的執行結果
        def check_recv(self, ...): ...
```



#### fuzzer/

資料夾底下還有一些資料夾與檔案，根據**功能**大致上可以分成以下部分：

- **Communicator** - 包裝資源存取的形式，並建立 `class Message` 描述傳送資訊的格式
- **Master** - 向 slave 發號施令，實作 fuzzing 策略
- **Slave** - 執行 QEMU instance 並聽 master 的命令
- **Mapserver** - 更新執行狀態與 coverage

主要是因為可以執行多個 QEMU 做平行化，因此才需要有一個 master process 負責管理，同時程式中也寫了不少用來預防 race condition 發生的程式碼。

如果是以檔案或目錄區分，則分成：

- **technique/** - 存放 payload 的 bitflip、arith 等常見的 mutation 操作
- **process/** - master、slave 與 mapserver
- **communicator.py** - 部分資源的使用包裝與初始化，像是 shared memory 就能用 function `get_bitmap_shm()`來存取

接下來就挑實作 mapserver 的 mapserver.py、 實作 master 的 master.py、實作 slave 的 slave.py 以及實作 communicator 的 communicator.py 來做介紹。

---



**Communicator** 實作在 communicator.py，主要是負責各個 component 的溝通，但我認為用來傳資料的 queue 設計的不太好，不同名稱的 queue 容易讓人造成誤會，因此讀者只需要記得每個 component 之間是用 queue 來傳送資料。程式碼如下：

```python
class Communicator:
    def __init__(self, ...):
        # 雖然一共只有 master、slave 與 mapserver，不過卻有一些看似會重複使用的 queue
        # 大概能猜測到是為了加速，因為有些資訊可能只會有 A 傳給 B
        self.to_update_queue = multiprocessing.Queue()
        self.to_master_queue = multiprocessing.Queue()
        self.to_master_from_mapserver_queue = multiprocessing.Queue()
        self.to_master_from_slave_queue = multiprocessing.Queue()
        self.to_mapserver_queue = multiprocessing.Queue()
        
        # 取得 shared memory
        # master shm (shared memory) 用來傳 payload 給 VM 中的 agent
        def get_master_payload_shm(self, slave_id):
        # mapserver shm 用來儲存 interesting payload
		def get_mapserver_payload_shm(self, slave_id):
        # 取得 bitmap shm
        def get_bitmap_shm(self, slave_id):
        # 建立 shm
        def create_shm(self):
```



**Master** 實作在 master.py，管理 slave 並下達命令：

```python
class MasterProcess:
    def __init__(self, comm):
        # comm 為 communicator
        self.comm = comm
        self.kafl_state = State()
        self.payload = ""

        # 紀錄用來做效能評估的執行狀態
        self.counter = 0
        self.round_counter = 0
		# ...

        # 讀取設定檔中客製化 fuzzing 策略的參數值
        self.config = FuzzerConfiguration()
        self.skip_zero = self.config.argument_values['s']
		# ...
        
        # 做 mutation，以下列兩個 function 為例
        def __bitflip_handler(self, ...):
		def __arithmetic_handler(self, ...):
        # performance 的測量
        def __perform_bechmark(self):
        def __perform_sampling(self):
        # 送 mutate 後的 payload 給 slave
        def __task_send(self, tasks, qid, dest):
```



**Slave** 實作於 slave.py，接收 master 命令並執行：

```python
class SlaveProcess:
    def __init__(self, comm, slave_id, auto_reload=False):
        self.config = FuzzerConfiguration()
        # communicator
        self.comm = comm
        self.slave_id = slave_id
        # 一個 qemu instance 就代表一台 VM
        self.q = qemu(self.slave_id, self.config)
	# 負責送 payload 並新增 interesting payload 到 mapserver shm
	def __respond_job_req(self, response):
    # 等待 master 命令的迴圈
    def interprocess_proto_handler(self):
        # 從 master 傳來的命令
        response = recv_msg(self.comm.to_slave_queues[self.slave_id])
        # tag 代表不同類型的命令，像是 KAFL_TAG_JOB 就是送 payload 給 agent
        if response.tag == KAFL_TAG_JOB:
            self.__respond_job_req(response)
            send_msg(KAFL_TAG_REQ, self.q.qemu_id, self.comm.to_master_queue, source=self.slave_id)
		# ...
        elif response.tag == KAFL_TAG_REQ_BENCHMARK:
            self.__respond_benchmark_req(response)
```



最後一個為實作 **mapserver** 的 mapserver.py，主要管理 fuzzing 結果的更新，並且還需要同步每個 slave 的狀態，其他 component 會透過 `to_mapserver_queue` 傳送請求給 mapserver ：

```python
class MapserverProcess:
    def __init__(self, comm, initial=True):
        self.comm = comm
        self.mapserver_state_obj = MapserverState()
        # 大多都與 fuzzing 結果的處理有關係，感覺與 performance 測量有部分重疊
        self.hash_list = set()
        self.crash_list = []
        self.shadow_map = set()
        # ...

	# 用來分析執行結果
	def __result_tag_handler(self, request):
	def loop(self):
        while True:
            self.__sync_handler()
            # 接收請求
            request = recv_msg(self.comm.to_mapserver_queue)
			# 舉例來說，slave 執行結束後就會送 KAFL_TAG_RESULT 請求給 mapserver，
            # mapserver 就會呼叫對應的 handler (__result_tag_handler) 來分析執行結果
            if request.tag == KAFL_TAG_RESULT:
                self.__result_tag_handler(request)
            elif request.tag == KAFL_TAG_MAP_INFO:
			# ...
```



### 總結

這兩天迅速對 kAFL 做簡單的介紹，我個人認為並不用深入了解 kAFL-fuzzer 這個部分怎麼處理，一方面是沒有註解，看得很辛苦，一方面是架構與效能還可以優化。比較值得花時間看的反而是 QEMU-PT 與 KVM-PT 做的事情，了解 patch 做了哪些事能夠更了解虛擬化技術以及 Intel-PT，而我在文章沒有講負責解析 Intel-PT 產生出來 packet 的程式碼，但那個部分也可以稍微看一下，雖然行為只是根據 Intel-PT 封包格式做處理，但如果知道程式碼要怎麼寫，應該會對 Intel-PT 有更深入的了解。

