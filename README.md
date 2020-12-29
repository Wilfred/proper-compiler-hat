# ELFish

An extremely simple compiler that translates a small language
("Wilfred Lisp") to x86-64 ELF executables.

Binaries use Linux syscalls directly. They have no external
dependencies (not even libc) but are completely unportable.
