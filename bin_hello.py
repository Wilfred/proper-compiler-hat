#!/usr/bin/env python

import os
import sys
import string


STRING = "STRING"
SYMBOL = "SYMBOL"
LIST = "LIST"


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
            if token is None:
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


def parse_from(tokens, i):
    """Return a nested list of lists representing a parse tree, plus an
    index of the next token to consume. `i` represents the first token
    index.

    >>> parse_from(["(", "foo", ")"], 0)
    (3, [("SYMBOL", "foo")])

    """
    print(i)
    token = tokens[i]

    if token == '(':
        i += 1
        result = []
        while True:
            if i >= len(tokens):
                assert False, "Missing closing paren )"
            if tokens[i] == ')':
                return (i + 1, (LIST, result))
            
            next_i, subtree = parse_from(tokens, i)
            result.append(subtree)
            i = next_i
    elif token == ')':
        assert False, "Unbalanced parens: {}".format(tokens[i:])
    elif token.startswith('"'):
        # string literal
        return (i + 1, (STRING, unescape(token)))
    else:
        # symbol
        return (i + 1, (SYMBOL, token))


def parse(tokens):
    _, result = parse_from(tokens, 0)
    return result


def int_64bit(num):
    """Return `num` as a list of bytes of its 64-bit representation.

    """
    assert num >= 0, "Signed numbers are not supported"
    return list(num.to_bytes(8, 'little'))


def elf_header_instructions(main_instructions):
    # The raw bytes of the ELF header. We use strings
    # for placeholder values computed later.
    header = [
        0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, # ELF magic number
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, # ELF reserved
        
        0x02, 0x00, # e_type: Executable file
        0x3e, 0x00, # e_machine: AMD64
        0x01, 0x00, 0x00, 0x00, # e_version: 1
        0x78, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, # e_entry (program entry address, 0x78, header size + 1)
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, # e_phoff (program header offset, 0x40)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, # e_shoff (no section headers)
        
        0x00, 0x00, 0x00, 0x00, # e_flags (no flags)
        0x40, 0x00, # e_ehsize (ELF header size, 0x40)
        0x38, 0x00, # e_phentsize (program header size)
        0x01, 0x00, # e_phnum
        0x00, 0x00, # e_shentsize
        0x00, 0x00, # e_shnum
        0x00, 0x00, # e_shstrndx
        
        0x01, 0x00, 0x00, 0x00, # p_type (loadable segment)
        0x05, 0x00, 0x00, 0x00, # p_flags (read and execute)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, # p_offset
        0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, # p_vaddr (start of current section)
        0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, # p_paddr (start of current section)
        'prog_length', # p_filesz, the file size (8 bytes) # WRONG!
        'prog_length', # p_memsz, the file size (8 bytes)
        0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, # p_align
    ]

    result = []
    for byte in header:
        if isinstance(byte, int):
            result.append(byte)
        elif byte == 'prog_length':
            result.extend(int_64bit(len(main_instructions)))
        else:
            assert False, "Invalid byte in header: {!r}".format(byte)

    return result


def main_fun_instructions(message_bytes):
    # The raw bytes of the instructions for the main function.
    main_fun = [
        0xb8, 0x01, 0x00, 0x00, 0x00, # mov $1 %eax (1 = sys_write)
        0xbf, 0x01, 0x00, 0x00, 0x00, # mov $1 %edi (1 = stdout)
        # mov $0x40009f %rsi (address of message)
        0x48, 0xbe] + int_64bit(0x40009f) + [

        # mov len(message) %edx
        0xba, len(message_bytes), 0x00, 0x00, 0x00,
        0x0f, 0x05, # syscall (1 = sys_write)
        
        0xb8, 0x3c, 0x00, 0x00, 0x00, # mov $60 %eax (60 = sys_exit)
        0xbf, 0x00, 0x00, 0x00, 0x00, # mov $0 %edi
        0x0f, 0x05, # syscall
        # TODO: put message bytes in a separate section?
    ] + list(message_bytes)

    return main_fun


def main(filename):
    with open(filename) as f:
        src = f.read()

    tokens = list(lex(src))
    message = unescape(tokens[-2].strip('"'))
    message_bytes = bytes(message, 'ascii')

    main_fun = main_fun_instructions(message_bytes)
    header = elf_header_instructions(main_fun)

    with open('hello', 'wb') as f:
        f.write(bytes(header))
        f.write(bytes(main_fun))

    os.chmod('hello', 0o744)

    print("Wrote hello ELF")


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: {} <path>".format(sys.argv[0]))
        sys.exit(1)
    
    main(sys.argv[1])
