# fuzzing-learning-in-30-days

這些文章是我在 2022 年參加 IThome 鐵人賽所撰寫的系列文，內容概括了基礎的模糊測試相關知識，並以大量的"查閱原始碼"來了解內部機制，希望對一些想了解模糊測試底層實作的人有幫助。

- [[Day 1] 模糊測試概念總覽](Day1.md)
- [[Day 2] Fuzzing 內部架構](Day2.md)
- [[Day 3] 透過 Sanitizer 偵測程式異常](Day3.md)
- [[Day 4] 近代 fuzzer 始祖 - AFL - 總覽 & 編譯](Day4.md)
- [[Day 5] 近代 fuzzer 始祖 - AFL - 插樁 & 組譯](Day5.md)
- [[Day 6] 近代 fuzzer 始祖 - AFL - 插樁程式碼](Day6.md)
- [[Day 7] 近代 fuzzer 始祖 - AFL - Fuzzer - 初始化 & Fuzzing loop](Day7.md)
- [[Day 8] 近代 fuzzer 始祖 - AFL - Fuzzer - 校正 & Fork server](Day8.md)
- [[Day 9] 近代 fuzzer 始祖 - AFL - Fuzzer - Trimming & Mutation](Day9.md)
- [[Day 10] 近代 fuzzer 始祖 - AFL - Fuzzer - Interesting input](Day10.md)
- [[Day 11] Coverage-guided fuzzer - 對 source-code 程式做模糊測試](Day11.md)
- [[Day 12] Coverage-guided fuzzer - 對 binary-only 程式做模糊測試 - Static binary rewriting](Day12.md)
- [[Day 13] Coverage-guided fuzzer - 對 binary-only 程式做模糊測試 - Dynamic binary instrumentation (上)](Day13.md)
- [[Day 14] Coverage-guided fuzzer - 對 binary-only 程式做模糊測試 - Dynamic binary instrumentation (下)](Day14.md)
- [[Day 15] Coverage-guided fuzzer - 對 binary-only 程式做模糊測試 - Other](Day15.md)
- [[Day 16] 優化找 coverage 的能力 - 污點分析 Taint analysis](Day16.md)
- [[Day 17] 優化找 coverage 的能力 - 符號執行 Symbolic execution & 實際運用的困難](Day17.md)
- [[Day 18] 優化找 coverage 的能力 - 鏈結時期優化 (LTO)](Day18.md)
- [[Day 19] 優化找 coverage 的能力 - REDQUEEN](Day19.md)
- [[Day 20] 優化 seed selection](Day20.md)
- [[Day 21] 優化 mutation - MOpt](Day21.md)
- [[Day 22] OS fuzzer - kAFL 論文 - 概念總覽 & 背景知識](Day22.md)
- [[Day 23] OS fuzzer - kAFL 論文 - 設計框架 & 實驗結果](Day23.md)
- [[Day 24] OS fuzzer - kAFL 原始碼 - Patched QEMU & KVM](Day24.md)
- [[Day 25] OS fuzzer - kAFL 原始碼 - The fuzzer](Day25.md)
- [[Day 26] OS fuzzer - syzkaller - 介紹 & 執行環境建置](Day26.md)
- [[Day 27] OS fuzzer - syzkaller - syzlang & syz-manager](Day27.md)
- [[Day 28] OS fuzzer - syzkaller - syz-fuzzer & syz-executor](Day28.md)
- [[Day 29] Hypervisor fuzzer - Nyx](Day29.md)
- [[Day 30] Hypervisor fuzzer - Hypercube 與參賽心得](Day30.md)

基本上文章內容極少參考第二手資料，如果內容有誤就代表我還沒完全理解，麻煩通知我一聲或是開 issue 討論，謝謝！

> 鐵人賽連結： https://ithelp.ithome.com.tw/users/20151153/ironman/5164
