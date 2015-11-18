;   -------------------------------------
;   tproc - Tiny Windows Process Viewer
;   Copyright (C) 2015 Chris Andrews
;   -------------------------------------

format	PE CONSOLE 4.0 
entry	start 
stack	4000h, 4000h 

include 'include/win32a.inc'

virtual at 0 
PROCESSENTRY32: 
    .dwSize	    dd	?
    .dwUnused1	    dd	?
    .dwProcessID    dd	?
    .dwUnused2	    dd	?
    .dwUnused3	    dd	?
    .dwNumThreads   dd	? 
    .dwParentID     dd	? 
    .lBasePriCls    dd	? 
    .dwUnused4	    dd	? 
    .szExeFile	    rb	MAX_PATH 
    .size = $ 
end virtual

section '.data' data readable writeable 

    listdata	db  '%30s : PID : %d',0Dh,0Ah,0
    titleline	db  '%42s',0Dh,0Ah,0
    titlebreak	db  '==========================',0Dh, 0Ah, 0
    maintext	db  'tproc process viewer %s',0Dh,0Ah,0
    version	db  '1.0',0Dh,0Ah,0
    flag	rb  1

section '.code' code readable executable 

align 32 
start:
    xor 	eax, eax
    mov 	eax, version
    cinvoke	printf, maintext, eax
    ; Get snapshot of all running processes
    invoke	CreateToolhelp32Snapshot, 2, 0
    mov 	ebx, eax
    ; Allocate pren32 to stack and set EDI to it
    sub 	esp, PROCESSENTRY32.size 
    mov 	edi, esp
    ; Get first process info
    mov 	[edi + PROCESSENTRY32.dwSize], PROCESSENTRY32.size 
    invoke	Process32First, ebx, edi
    test	eax, eax 
    jz		.finish
    mov 	[flag], 1

.listall:
    lea 	eax, [edi + PROCESSENTRY32.szExeFile]
    ; Loop to return all processes
    cinvoke	printf, listdata, eax, [edi + PROCESSENTRY32.dwProcessID]
    cmp 	[flag], 1
    je		.titlebreak

.nextproc:
    invoke	Process32Next, ebx, edi
    test	eax, eax
    jnz 	.listall

.finish:
    ; Restore the stack
    add 	esp, PROCESSENTRY32.size
    ; Close Toolhelp32Snapshot handle
    invoke	CloseHandle, ebx
    invoke	ExitProcess, 0

.titlebreak:
    push	eax
    xor 	eax, eax
    mov 	eax, titlebreak
    cinvoke	printf, titleline, eax
    pop 	eax
    mov 	[flag], 0
    jmp 	.nextproc

section '.idata' import data readable writeable

    library   kernel32,'KERNEL32.DLL',msclib,'MSVCRT.DLL'
    import    msclib,printf,'printf' 
    import    kernel32,CreateToolhelp32Snapshot,'CreateToolhelp32Snapshot',\ 
	      CloseHandle,'CloseHandle',\ 
	      OpenProcess,'OpenProcess',\ 
	      Process32First,'Process32First',\ 
	      Process32Next,'Process32Next',\ 
	      ExitProcess,'ExitProcess' 
