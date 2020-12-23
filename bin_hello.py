#!/usr/bin/env python

import os
import sys
import string


def unescape(string_lit):
    res = ""
    i = 0
    while i < len(string_lit):
        c = string_lit[i]
        if c == "\\":
            assert i < len(string_lit) - 1, "Backslash without following char"
            if string_lit[i + 1] == "n":
                res = res + "\n"
                i += 2
            else:
                assert False, "Invalid escape sequence"
        else:
            res = res + c
            i += 1
    return res


def lex(src):
    token = None

    i = 0
    while i < len(src):
        c = src[i]
        if c in ['(', ')']:
            yield c
            token = None
            i += 1
        elif c in [' ', '\n']:
            if token:
                yield token
                token = None
            i += 1
        elif c in string.ascii_letters or c in string.digits or c in ['!', '?']:
            if token == None:
                token = c
            else:
                token = token + c
            i += 1
        elif c == '"':
            end_i = i + 1
            while end_i < len(src) and src[end_i] != '"':
                end_i += 1

            assert src[end_i] == '"'
            yield src[i:end_i]
            i = end_i + 1
        else:
            assert False, "Could not lex: {!r}".format(src[i:])
        

def program_instructions(message):
    message_bytes = bytes(message, 'ascii')

    # The raw bytes of the instructions of the program. We use strings
    # for placeholder values computed later.
    prog = [
        0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, # ELF magic number
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, # ELF reserved
        
        0x02, 0x00, # e_type: Executable file
        0x3e, 0x00, # e_machine: AMD64
        0x01, 0x00, 0x00, 0x00, # e_version: 1
        0x78, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, # e_entry (program entry address)
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x38, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
        'prog_length', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, # p_filesz, the file size (173)
        'prog_length', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, # p_memsz, the file size (173)
        0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, # p_align
        # end ELF header

        0xb8, 0x01, 0x00, 0x00, 0x00, # mov $1 %eax
        0xbf, 0x01, 0x00, 0x00, 0x00, # mov $1 %edi
        0x48, 0xbe, 0x9f, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, # mov $0 %rsi

        # mov len(message) %edx
        0xba, len(message_bytes), 0x00, 0x00, 0x00,

        0x0f, 0x05, # syscall
        0xb8, 0x3c, 0x00, 0x00, 0x00, # mov $1 %eax
        0xbf, 0x00, 0x00, 0x00, 0x00, # mov $0 %edi

        0x0f, 0x05, # syscall
    ] + list(message_bytes)

    prog_length = len(prog)

    # Set the program length now we know it.
    prog = [
        prog_length if b == 'prog_length' else b
        for b in prog
    ]
    
    return prog


def main(filename):
    with open(filename) as f:
        src = f.read()

    tokens = list(lex(src))
    message = unescape(tokens[-2].strip('"'))
    instructions = program_instructions(message)

    with open('hello', 'wb') as f:
        f.write(bytes(instructions))

    os.chmod('hello', 0o744)

    print("Wrote hello ELF")


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: {} <path>".format(sys.argv[0]))
        sys.exit(1)
    
    main(sys.argv[1])
