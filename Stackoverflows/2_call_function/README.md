## CSAW16: Warmup

This is a basic controlling the instruction pointer buffer overflow. I use ghidra to find the exact amount of bytes I need to overflow the buffer by to 
reach the return address in the stack and craft my payload accordingly.There is an easy function that just prints out the contents of the flag.txt file 
which gives me the flag.

![image](https://github.com/KiranbaskarV/Nightmare/assets/41965706/27d8c08d-8eb6-40db-a107-7edbebfc7108)

Ghidra tells me the offset to the return address (or start of the stack frame) is `0x48` bytes from the buffer being read by `gets` which means I need 
to put `0x48` bytes of data before overwriting the return address with an address of my choice.

![image](https://github.com/KiranbaskarV/Nightmare/assets/41965706/c6d7b1c5-8c7e-4562-b194-40979a6523c5)

From the decompiled code I also see that the buffer size is 64 bytes, so I need 64 bytes of padding, 8 bytes of RBP overwrite which gives me `0x48` bytes. 
I add in an extra return in between to make the stack aligned to 16 bytes. The original intended solution did not require this extra return instruction. 
I will explain my understanding of why this instruction is needed.

Essentially you want to make sure your stack is 16-byte aligned. This is needed because of a alignment check carried out by the specific implementation of libc,
present in the newer versions of the library (post 2016, when this competition was held.). This alignment check happens in the 64 bit calling convention. ([source](https://ropemporium.com/guide.html#Common%20pitfalls)) 
You can ensure alignment by either adding an extra ret instruction in between (which will add 8 bytes to your old payload, making the stack 16-byte aligned) 
or just skip the first push rbp instruction in the easy function (which will subtract 8 bytes from what the stack would have been normally as you don't push rbp onto 
the stack anymore). Also judging by [this thread](https://www.reddit.com/r/LiveOverflow/comments/g3z2t7/stack_alignment_question/) this is an issue that is
faced with newer versions of libc, hence why it wasn't an issue in csaw16 (which most likely used libc 2.23 or a version which didn't have this issue).

![image](https://github.com/KiranbaskarV/Nightmare/assets/41965706/bdbe60c9-dfb2-4dac-a25e-697569d3affb)

## CSAW18: Getit

Pretty similar process as before, and this problem also has the same problem as the last one. The function of interest here spawns a shell:

![image](https://github.com/KiranbaskarV/Nightmare/assets/41965706/5b071c76-2047-4cc9-9772-21b2cd5b34c0)

And the offset to return addres is `0x28` bytes this time:

![image](https://github.com/KiranbaskarV/Nightmare/assets/41965706/225752ce-5c23-41a0-aa85-606ff68aa20c)

I craft the payload without the extra return instrction and skip the push rbp instruction and jump one extra byte from the start of give_shell instead. I just wanted to try
out both the ways to see if they worked, and they do indeed.

![image](https://github.com/KiranbaskarV/Nightmare/assets/41965706/010523f2-7e17-4eb3-a9cf-698923cbda56)

## tuctf 2017: Vulnchat

This was a cool challenge and required a 2 separate buffer overflows to solve. Since there is a format specifier string stored in the stack with a length specified,
the amount of characters being read in was limited. I do a buffer overflow first to overwrite this format specifier itself and increase the length of the input that 
can be read, and then I perform the 2nd buffer overflow that will actually overwrite the return address in the stack. The goal is once again a printFlag function:

![image](https://github.com/KiranbaskarV/Nightmare/assets/41965706/2fd9d5a4-49ea-4e5c-9e4d-d17e3a5e3f19)

![image](https://github.com/KiranbaskarV/Nightmare/assets/41965706/ff5d3b20-dc46-4c02-a8db-8d6cb11e0613)

The first buffer overflow happens in the username and the second in the reply to the djinn. Ghidra gives me the offsets for the buffers I am interested in:

![image](https://github.com/KiranbaskarV/Nightmare/assets/41965706/ac9e38a1-c62f-4801-a9a3-329a6f24d58c)

![image](https://github.com/KiranbaskarV/Nightmare/assets/41965706/8428427c-ab3c-4f19-8976-b0ade8d06636)



