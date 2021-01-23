# PEB-Walk

This project was inspired due to the lack of documentation around this subject.

I'll document my learning process from simply accessing the PEB, to dynamically solving the IAT (a common technique used by malware authors).

### Current Version:
After lots of head-aches my code can finally retrieve the `LoadLibraryA` function from kernel32.dll and load `user32.dll`.

### Next objectives:
* Make a more modularized code, as of right now it's too hard coded.
* Maybe implement some sort of hashing in the strings.
* Dinamically import functions and store them in a user-made table (simulate IAT).
