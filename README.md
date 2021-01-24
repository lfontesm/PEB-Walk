# PEB-Walk

This project was inspired due to the lack of documentation around this subject. As an aspiring malware analyst, it hurt my ego that everytime I booted IDA or Ghidra and saw `mov eax, fs[0x30] ... mov esi, [eax+0x3c]` I had no idea how they implemented it. Of course I could implement it in MASM, since the source code is literally right there, but I also wanted to do it in C/C++, because why not?

I'll document my learning process from simply accessing the PEB, to dynamically solving the IAT (a common technique used by malware authors).

### Current Version:
After lots of head-aches my code can finally retrieve the `LoadLibraryA` function from kernel32.dll and load `user32.dll`.

* IDA View:

![Screenshot_20210123_182530](https://user-images.githubusercontent.com/28660375/105614462-62e51000-5da8-11eb-8a4c-317510ac1d3f.png)

* x64dbg View:
  * Before the function call:
  
![Screenshot_20210123_182748](https://user-images.githubusercontent.com/28660375/105614522-b6eff480-5da8-11eb-88a2-d59a80b63253.png)
  * Content on the registers:
  
![Screenshot_20210123_182909](https://user-images.githubusercontent.com/28660375/105614549-e6066600-5da8-11eb-8809-73b44028be8b.png)
  * Content on stack:
  
![Screenshot_20210123_182947](https://user-images.githubusercontent.com/28660375/105614561-fc142680-5da8-11eb-828b-426edbb3069a.png)

### Next objectives:
* Make it work for a 64-bit machine.
* Make a more modularized code, as of right now it's too hard coded.
* Maybe implement some sort of hashing in the strings.
* Dinamically import functions and store them in a user-made table (simulate IAT).

---

[This](https://github.com/corkami/pics/blob/master/binary/pe102/pe102.svg) visual documentation by @Corkami is also incredible and will help understand the code.
