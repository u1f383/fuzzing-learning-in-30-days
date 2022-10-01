# [Day 1] 模糊測試概念總覽

> 此系列文的主題為模糊測試，內容包含但不限於其概念、實作以及演進，對象設定在有一定程式基礎的人。看完後至少會知道模糊測試怎麼運作，如果能完整消化的話，應該就已經具備大部分的模糊測試知識。



模糊測試又稱作 fuzzing，是一種**軟體測試**技術。其核心概念為**自動產生隨機輸入**到一個程式中，並監視程式異常，如 crash、assertion failed，以發現可能的程式錯誤。

簡單舉個例子，檔案 **test.c** 是你要測試程式的原始碼，從 stdin 讀取 8 bytes 後印出，但印出前會比較輸入 (`input`) (1) 的前兩個 bytes 是否為 `AB`，如果是的話就會執行到寫壞的程式碼 (2)，並觸發 segmentation fault 結束程式。在此 (1) 對應到真實程式的某些執行條件，(2) 對應到有問題的爛 code。

test.c：

```c
// gcc -o test test.c
#include <unistd.h>

int main()
{
    char input[8] = {0};
    read(STDIN_FILENO, input, 8);
    if (input[0] == 'A' && input[1] == 'B') // (1)
        *((unsigned int *)0) = 0xdeadbeef; // (2)
    write(STDOUT_FILENO, input, 8);
    return 0;
}
```



但實際上大型程式往往上百萬行，中小型至少也會有數千數萬行，一行一行找實在是太慢了，將這種測試自動化才是可行之舉，因此才有模糊測試的出現。模糊測試就是自動去 1. 執行目標程式、2. 餵入的 input、3. 回報執行結果，而負責做這些事情的程式稱為 fuzzer，並且根據開發或是執行效率，會選擇用不同的語言來實作。

對於 test.c，我們用 python 實作一個 fuzzer **fuzzer.py** 自動去對 **test** 進行模糊測試，嘗試餵入 `inps` 的每個 element，並由 exit status (1) 判斷 **test** 是否發生執行異常，最終會找到 element `'AB'` 會觸發異常行為。

fuzzer.py：

```python
import subprocess

target = './test'
inps = ['AA', 'BB', 'BA', 'AB']

for inp in inps:
    try:
        subprocess.run([target], input=inp.encode(), capture_output=True, check=True)
    except subprocess.CalledProcessError: # (1)
        print(f"bug found with input: '{inp}'")

# (output)
# bug found with input: 'AB'
```



在模糊測試之前，為了檢測**程式的功能**是否正常運作，因此會寫一些測試腳本或是 **Unit Test**，這與模糊測試的方向不太一樣，前者為找程式異常，後者單純測試程式所提供的功能是否正常執行。

而這也跟模糊測試被歸類在 Security 有關係，在一般情況下使用者會照**正常使用**的方式去使用服務，因此 Unit Test 通過後就代表服務能正常運作，滿足使用者的需求。然而並不是所有使用者都會正常使用，如果程式並沒有檢查這些非預期的使用方式，讓程式中存在一些漏洞，小則能讓服務終止，大則讓攻擊者取得主機控制權。模糊測試的概念正好符合攻擊者的角度，執行程式並餵入隨機產生的 input，並從執行結果檢查當前 input 是否讓程式滿足觸發漏洞的條件。

簡而言之，模糊測試被拿來找程式漏洞，讓程式開發員能盡快修補，避免被攻擊者所利用。

