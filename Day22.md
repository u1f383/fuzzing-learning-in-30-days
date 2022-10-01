# [Day 22] OS fuzzer - kAFL 論文 - 概念總覽 & 背景知識



先前介紹的 fuzzer 如果沒有特別說明，基本上目標都是執行在 userspace 的程式，然而當 fuzzing 這個主題越來越熱門，開始有研究人員思考是否可以把這個概念實作在不同層級的目標，因為只要目標有辦法餵入輸入並取得 feedback (也許不限於 coverage)，就能透過 fuzzer 逐步調整 input，讓目標執行到更廣更深的處理，同時先前研究的優化方法也能重新使用。在這個概念上，針對各種會需要執行程式，並且有辦法得到輸出的目標，都能嘗試接上 fuzzer 自動化找程式漏洞，例如 IOT fuzzer、firmware fuzzer 等各式各樣的 fuzzer，也包含這幾天要介紹的 OS fuzzer (kernel fuzzer) 與 hypervisor fuzzer，而 OS 又因為大多數的情況一定會用到，因此 OS fuzzer 的研究又特別熱門。

如果將 OS 視為一個 codebase 很大的程式，撇開 interrupt handler 那種基礎機制不說，程式的輸入就是來自 userspace 的 system call，輸出直觀來看就是 return code，代表有沒有成功執行。

如果將 hypervisor 視為目標，那輸入基本上就是在虛擬機中使用 PIO 或 MMIO 對模擬的硬體設備做存取，輸出就是看硬體設備暫存器所存放的回傳值。



## OS fuzzer

**OS fuzzer** 泛指以 OS 為 fuzzing 對象的 fuzzer，並且 OS 不限於 Linux，其他像是以 Windows、FreeBSD 為目標的 fuzzer 也算在內，不過這邊基本上只會介紹 Linux fuzzer。在我的知識範圍中，最著代表性的兩個 Linux kernel fuzzer 分別是 [kAFL](https://github.com/RUB-SysSec/kAFL) 與 [syzkaller](https://github.com/google/syzkaller)，兩者都是以 Linux kernel 為目標 (雖然現在也支援其他作業系統)，前者全名為 kernel-AFL，從名字就能知道它的重要性；後者為 google 開發的 fuzzing 框架，具有效能不差、好部署、資訊完全、客製化方便等優點，成為了目前 Linux kernel fuzzer 的龍頭。

雖然現在直接 google 搜尋 "linux kernel fuzzer"，大概有一半的結果都與 syzkaller 有關，但稍微推算一下時間，kAFL 應該是早於 syzkaller 開始，並在 OS fuzzer 討論初期為相較成熟的 fuzzer。接下來會介紹 kAFL 使用到的機制與實作方式，一開始以論文 [kAFL: Hardware-Assisted Feedback Fuzzing for OS Kernels](https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-schumilo.pdf) 介紹整個框架，而後透過原始碼來深入了解內部運作。



>kAFL 為 2017 年發表論文，因此在 2016 年時應該就實作的差不多了，反之 syzkaller 雖然在 [2016 年](https://blog.linuxplumbersconf.org/2016/ocw/system/presentations/3561/original/Syzkaller.pdf)被提出來，但到了 2018 年有較為成熟的框架。



## kAFL paper

### Introduction

可以將整個 kernel fuzzing 的執行流程拆成下面幾個部分討論：

- **產生輸入** - 程式是透過 system call 餵 input 給作業系統，跟 userspace 程式單純吃 byte stream 或檔案不相同，因此對 kernel fuzzing 來說，要產生的輸入是 system call
- **餵進輸入** - 呼叫一連串產生出來的 system call sequence
- **得到回饋** - 一般來說 system call 的執行結果會是回傳值，但 fuzzing 想要得到的是 code coverage

與先前所介紹的 fuzzing 知識結合，能提出一些關鍵問題以及可能解法：

- **產生輸入**
  - 如果是單純產生 system call 很簡單，但要產生**有意義**的 system call 很難，各個 system call 都有自己的參數與使用條件，像是 `read()` 會需要合法的 file descriptor，如果直接傳入記憶體位址或是 fd 非法都會失敗
  - 如果能產生有意義的 system call 參數，字串的變異方式應該會需要跟整數的不相同，怎麼對不同型態的參數做 mutation 才會有意義
    - 針對不同型態的設計不同的 mutation 操作
  - 如果能取得 code coverage，則 seed selection 並不會有什麼太大的問題
- **餵進輸入**
  - 會需要有一個程式需要持續呼叫 system call sequence，並在執行完該次的輸入後，要想辦法跟 fuzzer 取得下一次的輸入，這個程式被稱作 **harness**
    - 直觀的解法就是將產生出來的 sequence 做序列化後存到檔案中，再由 harness 反序列化後讀到程式內執行
- **得到回饋**
  - 如果 Linux kernel 當中已經有現成的 coverage collection feature 就可以直接拿來用，否則只能使用硬體或是 DBT 來蒐集
    - 根據 [lwn 文章](https://lwn.net/Articles/671640/)所述，KCOV 在 2016 年就已經支援，而開發人員就是 syzkaller 的維護者 [dvyukov](https://github.com/dvyukov)



### Background

首先 kAFL 一共使用到以下兩個主要的機制來建構 fuzzing 環境，而下方條列也對各機制做介紹：

- **Intel-VX** - 由 Intel 開發的硬體支援的模擬執行技術
  - 如果直接 fuzz host 環境，不但可能會因為 syscall 的操作弄髒環境，當戳到洞的時候有可能會因為 panic 導致系統沒有儲存到 input，因此通常 fuzzing OS 時會跑在虛擬機裡面
  - 在沒有硬體支援的情況下，通常會使用 system level 的虛擬化技術模擬作業系統的執行環境，相關的工具有 QEMU，其實底層就是 DBT 與硬體設備虛擬化的實作，雖然可行但就是執行效果不好
  - 如果有硬體支援，就可以執行一些特殊的 instruction，讓 CPU 建立虛擬機的環境並執行，這樣效果基本上跟原生 (native) 環境差不了多少
  - kAFL 避免效能太低，因此使用了 **Intel-VX** 來執行虛擬機
- **Intel-PT** - Intel 提供的追蹤程式特定行為的指令集 (Day15 有對 Intel-PT 做詳細介紹)
  - kAFL 選擇使用硬體指令集取得 coverage 而非 DBT，是因為 kernel 並非透過 DBT 執行
  - 目前透過 linux feature KCOV 可以做到 kernel code coverage collection，但可能因為該技術在當時沒有這麼成熟，所以 kAFL 沒有使用 (或者有可能因為是敵人開發的技術)



#### Hypervisor

對於沒有 hypervisor 相關知識的讀者，在此做一些基本的介紹。

虛擬化技術一開始只是因為過去硬體太貴，所以為了最大化硬體資源，有人想到是否可以在電腦裡面再開一台電腦，這樣如果需要使用兩台電腦的環境，就不用物理上再買另一台電腦了。隨著技術的開發，**QEMU** (Quick EMUlator) 成功做到在原本的作業系統上，以 userspace 的程式模擬運行另一個作業系統，這也稱作 full-system emulation。雖然能成功運行，但代價就是效能上面的不足，因為原本 native 環境也許只是一行 instruction 能做到的事情，但透過模擬執行就可能要數百數千行 instruction，因此一些 CPU 廠商就開始設計用硬體的方式執行虛擬環境，所以有了 **Intel-VX** 以及 **AMD-V** 的出現。此外 arm 指令集也能透過 EL2 的相關設定與操作，建置虛擬機的執行環境，細節請參考 [KVM/ARM: The Design and Implementation of the Linux ARM Hypervisor](http://www.cs.columbia.edu/~cdall/pubs/KVMARM_talk.pdf)。

上述的虛擬化技術只是淺層皮毛，實際上有非常多細節與機制沒有介紹到，不過做 overview 已經算足夠了。接下來介紹一些虛擬化技術的名詞定義：

- **VM (virtual machine)** - 正在被模擬執行的作業系統
- **Host** - 原本使用者所在的環境
- **Guest** - VM 內的環境
- **Virtual machine monitor (VMM, 又稱作 hypervisor)** - 在 host 執行的程式，負責將 VM 運行起來
- **Hypercall** - VM 用來請求 hypervisor 的一些特權操作，類似於 instruction `syscall` 的定位，只是將 userspace 與 kernel 的角色換成 hypervisor 與 VM



大量化簡後的 VM 與 VMM 互動如下圖：

<img src="/Users/u1f383/Library/Application Support/typora-user-images/image-20220923155106431.png" alt="image-20220923155106431" style="zoom:50%;" />

- 當 OS 跑在虛擬機後，guest 使用的作業系統會在 VM 裡面執行 (guest)，如果沒有特別設置，interrupt 也會在 VM 當中處理，不會跳到外面 (host)
- 若 VM 執行到特權指令 (`hypercall`)，則會發生 trap 到 host，之後將 trap 資訊轉給 hypervisor 做處理
- 當硬體暫存器與主機的 memory 做 mapping 後，就可以使用 MMIO / PIO 來存取硬體。如果嘗試在 VM 當中存取，因為兩者底層都是用模擬出來的 device handler 來處理，因此會先 trap 到 hypervisor，再由 hypervisor 的 device emulation component 模擬硬體行為



---

今天從設計者的角度分析 kernel fuzzer 的實作方式與挑戰，為虛擬化技術做了簡單的介紹，同時這些也是 kAFL 使用到的技術。明天會介紹論文提出的 kAFL 架構設計，並再透過 2~3 天的時間介紹原始碼，深入了解實作方法。

