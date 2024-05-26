## Csaw 2018 Quals: Boi

This one is fairly simple, all you have to do is overwrite the int value with `0xcafebaee`. Doing that, I get the flag

![[Pasted image 20240526175055.png]]

## TAMU'19: Pwn1

There's hardcoded string answers to the first two question which can be found by reversing the binary. The third one takes in an input where we overwrite a hardcoded local variable with the value that is expected (`-0x215eef38`). On doing that, we get the flage.

![[Pasted image 20240526175756.png]]


## TokyoWesterns'17: JustDoIt

The flag is read from a file into a static variable in memory. 

![[Pasted image 20240526182323.png]]

At the end there is a `puts` call to print the success message, so we just have to overwrite the address of local_14 with the address of the static variable `flag`. 

![[Pasted image 20240526182513.png]]