# PEB-Walk

This project was inspired due to the lack of documentation around this subject. As an aspiring malware analyst, it hurt my ego that everytime I booted IDA or Ghidra and saw `mov eax, fs[0x30] ... mov esi, [eax+0x3c]` I had no idea how they implemented it. Of course I could implement it in MASM, since the source code is literally right there, but I also wanted to do it in C/C++, because why not?

I'll document my learning process from simply accessing the PEB, to dynamically solving the IAT (a common technique used by malware authors).

The project has reached it's intended goal, which was to simulate a dynamic construction of the Import Address Table. But I'm still not satisfied, this is not enough. The next goals will be to transform this piece of code into a packer/dropper. And I will implement even more evasion techniques, namely, the easiest that comes to mind is process Injection, since there's tons of ways one could do it. I will keep updating with new ideas. But eventually I would love to be able to implement control-flow flattening.    

### Current Version:
Successfully building a data structure akin of an Import Table. Since the objetive of the project is too be as verbose as possible, I'm not going to completely eliminate all of the strings inside the image file, but the function lookup is now using a junior checksum to retrieve the function fom the export tables.
The checksum calculator I used was left in the code.

I also left a log sample for visual AID. It's not much and there's tons of lines in the file, but they are just the generated output of the functions being enumerated.

Executing the current version will pop a message box:

![Screenshot_20210125_143523](https://user-images.githubusercontent.com/28660375/105742821-bd9e7900-5f1a-11eb-970a-9e65ed618a70.png)

And I hope it's easy to understand how that happens.


In the screenshot below you can see how IDA decompiles the process of looking for LoadLibraryA

![Screenshot_20210125_144411](https://user-images.githubusercontent.com/28660375/105744479-f1c66980-5f1b-11eb-8e6e-a3e53f252361.png)

* x64dbg View:
   
 Before the function call:
  
![Screenshot_20210123_182748](https://user-images.githubusercontent.com/28660375/105614522-b6eff480-5da8-11eb-88a2-d59a80b63253.png)

   Content on the registers:
  
![Screenshot_20210123_182909](https://user-images.githubusercontent.com/28660375/105614549-e6066600-5da8-11eb-8809-73b44028be8b.png)

   Content on stack:
  
![Screenshot_20210123_182947](https://user-images.githubusercontent.com/28660375/105614561-fc142680-5da8-11eb-828b-426edbb3069a.png)

### Next objectives:
* Add support to 64-bit machines.
* Add other evasion techniques such as packing and process injection. I'm not very versed on process hollowing, process herpaderping (I think they are forms of injection) and control flow flattening, but I hope eventually I'm able to implement them.

---

[This](https://github.com/corkami/pics/blob/master/binary/pe102/pe102.svg) visual documentation by @Corkami is also incredible and will help understand the code.
