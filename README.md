
# AsmShellcodeLoader


文章：[静态恶意代码逃逸（第十一课）- 汇编语言编写Shellcode加载器](https://payloads.online/archivers/2022-02-16/1/)

## 编译 

```
nasm -f win32 .\main.asm
link.exe /OUT:"main.exe" /MACHINE:X86 /SUBSYSTEM:WINDOWS /NOLOGO /TLBID:1 /ENTRY:StartMain .\main.obj
```



