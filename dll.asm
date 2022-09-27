global DllMain
export DllMain

section .text use32

Export:
    call DllMain

DllMain:
    push ebp
    mov esp,ebp
    sub esp,0x40
    mov eax,0x01
    add eax,eax
    add esp,0x40
    pop ebp