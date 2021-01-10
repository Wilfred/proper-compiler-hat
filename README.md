<img align="right" width="200" height="200" src="https://github.com/Wilfred/proper-compiler-hat/blob/master/pch_hat.png?raw=true" alt="logo">

# Proper Compiler Hat

*Wearing a Proper Compiler Hat* refers to a program that emits machine
code directly. No external compiler backend (e.g. LLVM), no external
toolchain (e.g. nasm, gcc, ld). Written as a fun coding exercise.

It's not capable or clever, but it works for a tiny language ("Wilfred
Lisp") and produces x86-64 ELF executables.

Binaries use Linux syscalls directly. They have no external
dependencies (not even libc) but are completely unportable.

## License

All the code in this repository is under the MIT license, see LICENSE.txt.

Logo is [from Freepik](https://www.freepik.com/free-vector/gentelman-vintage-accessories-doodle-black-set_3888767.htm).
