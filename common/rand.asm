// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
.CODE

PUBLIC _rdrand
_rdrand PROC
; Subroutine Prologue
push rbp     ; Save the old base pointer value.
mov rbp, rsp ; Set the new base pointer value.
sub rsp, 4   ; Make room for one 4-byte local variable.

; Subroutine Body

Label1: rdrand rax 

jnc Label1 

mov rsp, rbp ; Deallocate local variables
pop rbp ; Restore the caller's base pointer value
ret
_rdrand ENDP

END










