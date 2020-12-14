# wows-deobfuscator
(Work in progress) Deobfuscator for wows pyc files

# Usage

python deobfuscator.py [INPUT]

# Description

This aims to deobfuscate a single .pyc file from WoWs. I described some of the inner workings on my blog, [here](https://lpcvoid.com/blog/0007_wows_python_reversing/index.html) and [here](https://lpcvoid.com/blog/0008_python_bytecode_dejunking/index.html). 

It will attempt to create multiple files, all of which correspond to a certain obfuscation layer. Please be aware that the final deobfuscation ("decrypted_stage3_fixed.pyc") will not be decompileable via uncompyle6 yet, as it stil contains junk code in a few places and this thing is not intelligent enough to NOP that yet.




