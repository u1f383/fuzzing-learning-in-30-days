# [Day 20] 優化 seed selection



Seed selection 指的是 fuzzer 從 input queue 當中挑選 input 的行為，而 fuzzer 會先挑哪個 input 是由 input 的價值 (或者說優先度) 來決定，不過如何恆定 input 的價值見仁見智，但通常都會把**執行時間**與**新增的 path 數量**考慮進去，如果程式會處理檔案，也會把**檔案大小**納入評分標準。

即使有數千個 seed selection algorithm，但衡量各自的品質也是難處之一，於是在 2014 年就有人發表論文 [Optimizing Seed Selection for Fuzzing](https://www.usenix.org/system/files/conference/usenixsecurity14/sec14-paper-rebert.pdf) 提出測量標準，並且透過相關的實驗得出某些常見演算法的好壞。

雖然先前沒有特別提到 hypervisor fuzzer 與 OS fuzzer，但必須知道的是，當 target 位於不同的 ring level (e.g. OS, hypervisor)，有可能會有專屬的 seed selection algorithm，像是 [MoonShine: Optimizing OS Fuzzer Seed Selection with Trace Distillation](https://www.usenix.org/conference/usenixsecurity18/presentation/pailoor) 就是針對 OS fuzzer 做優化，所以沒辦法實作在一般的 userspace fuzzer 或 hypervisor fuzzer。

接下來會介紹論文 [Optimizing Seed Selection for Fuzzing](https://www.usenix.org/system/files/conference/usenixsecurity14/sec14-paper-rebert.pdf)，了解其研究方法與過程，對整個 seed selection 的優化方式做 overview。



## Optimizing Seed Selection for Fuzzing

### Introduction

在此論文之前多多少少有做相關的研究，總結來說 **code coverage** 一定是第一個看的，畢竟執行速度在快、檔案在小，只要沒走到新的 path 都沒用。不過通常一個 seed 並不能代表整個執行狀態，因此論文中使用了 **set covering problem** 來更好的分析，下面就對論文提出的一些變數做介紹：

- 假設程式的輸入是一個檔案，使用者會先決定一個 `n`，代表每用 `n` 個檔案執行後就做一次 coverage 分析
- 以 `n = 6` 為例子，以數字作為 basic block 的編號的情況下，`S-N` 代表第 `N` 個檔案作為 input 時所執行到的 basic block
  - `S-1 = {1,2,3,4,5,6}`，代表走到 1 ... 6 的 basic block
- 變數 `X` 代表所有 `S-N` 的聯集，也就是這組 input 可以走到哪些 basic block
  - 同個數字的 basic block 可能會來自不同的檔案，代表這些檔案都能夠讓程式執行到該 basic block
- 將 `X` 嘗試用不同的 `S-N` 組合起來，並用 `C-M` 表示，也就是說如果 `C-1 = {S-1, S-2}`，就代表只需要 `S-1` 與 `S-2` 就能走到所有的 basic block
  - 在此情況下 `C-2 = {S-1, S-2, S-3}` 也滿足條件，雖然 `S-3` 並非必要

不過如果要求得最小的 `C-N`，就是要解 **minimal set covering problem (MSCP)**，但是這是一個 NP-hard problem，所以只能用一些估算的方式求得。而 MSCP 還有一個可選參數 `k`，`k-MSCP` 代表在 set 當中最多只能有 `k` 個元素，並且不在要求覆蓋所有的 basic block，而是求得最大值。

假設可以求出 MSCP 的多個解，又因為這些解當中的每個 seed 元素都有對應的屬性，像是執行時間、檔案大小等等，可以再透過 **weighted** MSCP (WMSCP) 求出不同 weight (i.e. 執行時間、檔案大小) 的最小 set，意即這組解的總共花的執行時間最少、檔案大小的總和最少等等。



### Algorithm

論文以下面幾種常見的 seed selection algorithm 作為測量對象，執行目標已經被設計成存在一些 bug，所有 algorithm 都接收 `|F|` 個檔案作為 seed，並使用其中的 `k` 個檔案做優化並測試：

- **MINSET**
- **TIME MINSET** - 執行時間最少的 MSCP 解
- **SIZE MINSET** - 檔案大小最小的 MSCP 解
- **PEACH SET** - 工具 peach 自己寫的演算法
- **RANDOM SET** - 隨便選 k 個
- **HOT SET** - 將每個 seed (`|F|`) 個別 fuzz 給定的時間 `t`，並以找到 bug 的數量取出前 `k` 個 seed



### Hypothesis

對於實驗，論文提出了四種實驗結果的假設：

- **MINSET > RANDOM** - 在參數 `k` 相同的情況下，MINSET 找 bug 能力比 RANDOM SET 好
- **MINSET 的 Beneﬁts > Cost** - 將 MINSET 的計算考慮進去後，成效還是會比一般的 fuzzing 好
- **MINSET Transferability** - 相同性質的兩個程式 A B，將程式 A 的 MINSET 給程式 B 使用，會有差不多的效果
- **MINSET Data Reduction** - 使用 MINSET 的效果比整個 seed `|F|` 還要好
  - 這個假設似乎跟第一點有部分重疊



### Quality

假設需要測試 A B 演算法，則最簡單的做法就是直接取出 seed subset，之後做 seed selection algorithm，執行相同時間後比較結果即可。然而研究人員認為這樣的方法雖然只能知道特定 subset 適合的 algorithm，並不能代表符合所有的情況。

因此研究人員決定在測量之前，先將所有的 seed `si` 個別執行給定的 `t` 時間，並記錄找到的 bug 數量，將前幾個找到最多 bug 的 seed 視為 **optimal case**，之後在實際測量是就以這組 seed 作為 **initial seed**，藉此可以找出各個演算法的 **upper bound**，確保實驗結果的公平。

論文中還有介紹求得 optimal case 的過程，不過中間摻雜許多數學運算，在此就不做介紹。



### Evaluation

1. **是否提出的 seed selection algorithm 比 random 好** - PEACH SET 跟 TIME MINSET 與 RANDOM 較為接近，剩下幾個都遠比 RANDOM 好
2. **哪個 seed selection algorithm 表現最好** - (UNWEIGHTED) MINSET
3. **Data reduction 是否有用** - 非常有用
4. **是否具有 Transferability** - 如果程式行為類似，並且輸入的檔案形式相同，MINSET 才具有轉移性 



## 結論

目前一般的 fuzzer 都已經會參考執行時間跟輸入大小來評估 input 價值，但就沒有額外使用 MINSET 做分析。如果想要更優化 seed selection，根據論文的實驗結果，可以實作演算法在靜態/動態挑出重要的幾個 seed 為 **MINSET**，並且以**輸入大小**為主要評估依據 (TIME MINSET 實驗結果較差)，這樣應該就能產生比較好的效果。
