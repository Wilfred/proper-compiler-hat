#!/usr/bin/env python

import os
import sys
import string


STRING = "STRING"
INTEGER = "INTEGER"
SYMBOL = "SYMBOL"
LIST = "LIST"

ENTRY_POINT = 0x400000


def unescape(string_lit):
    """Convert the source bytes of a string literal to a string value.

    >>> unescape('"foo\\n"')
    'foo\n'

    """
    string_lit = string_lit.strip('"')
    
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
            if token:
                yield token
                token = None
            yield c
            i += 1
        elif c in [' ', '\n', ';']:
            if token:
                yield token
                token = None
            if c == ';':
                while i < len(src) and src[i] != '\n':
                    i += 1
                
            i += 1
        elif c in string.ascii_letters or c in string.digits or c in ['!', '?', '+', '-']:
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
            yield src[i:end_i + 1]
            i = end_i + 1
        else:
            assert False, "Could not lex: {!r}".format(src[i:])


def is_int_literal(token):
    return all(c in string.digits
               for c in token)


def parse_from(tokens, i):
    """Return a nested list of lists representing a parse tree, plus an
    index of the next token to consume. `i` represents the first token
    index.

    >>> parse_from(["(", "foo", ")"], 0)
    (3, [("SYMBOL", "foo")])

    """
    token = tokens[i]

    if token == '(':
        i += 1
        result = []
        while True:
            if i >= len(tokens):
                assert False, "Missing closing paren )"
            if tokens[i] == ')':
                return (i + 1, (LIST, result))
            
            i, subtree = parse_from(tokens, i)
            result.append(subtree)
    elif token == ')':
        assert False, "Unbalanced parens: {}".format(tokens[i:])
    elif token.startswith('"'):
        # string literal
        return (i + 1, (STRING, unescape(token)))
    elif is_int_literal(token):
        return (i + 1, (INTEGER, int(token)))
    else:
        # symbol
        return (i + 1, (SYMBOL, token))


def parse(tokens):
    """Return a list of expressions from parsing this list of tokens.

    """
    result = []

    i = 0
    while i < len(tokens):
        i, subtree = parse_from(tokens, i)
        result.append(subtree)
    
    return result


def int_64bit(num):
    """Return `num` as a list of bytes of its 64-bit representation.

    """
    assert num >= 0, "Signed numbers are not supported"
    return list(num.to_bytes(8, 'little'))


def int_32bit(num):
    """Return `num` as a list of bytes of its 32-bit representation.

    """
    assert num >= 0, "Signed numbers are not supported"
    return list(num.to_bytes(4, 'little'))


def num_bytes(byte_tmpl):
    """Given a list of raw bytes and template strings, calculate the total number
    of bytes that the final output will have.

    Assumes all template strings are replaced by 8 bytes.

    >>> num_bytes([0x127, "prog_bytes"])
    9

    """
    return sum(1 if isinstance(b, int) else 8
               for b in byte_tmpl)


def elf_header_instructions(main_instructions, string_literals):
    # The raw bytes of the ELF header. We use strings
    # for placeholder values computed later.
    header_tmpl = [
        0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, # ELF magic number
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, # ELF reserved
        
        0x02, 0x00, # e_type: Executable file
        0x3e, 0x00, # e_machine: AMD64
        0x01, 0x00, 0x00, 0x00, # e_version: 1
        'prog_entry', # e_entry (program entry address, load offset + header size)
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
        'prog_length', # p_filesz, the file size (8 bytes)
        'prog_length', # p_memsz, the file size (8 bytes)
        0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, # p_align
    ]

    rodata_size = sum(len(lit) for lit in string_literals)
    prog_length = num_bytes(header_tmpl) + len(main_instructions) + rodata_size

    result = []
    for byte in header_tmpl:
        if isinstance(byte, int):
            result.append(byte)
        elif byte == 'prog_length':
            result.extend(int_64bit(prog_length))
        elif byte == 'prog_entry':
            result.extend(int_64bit(ENTRY_POINT + num_bytes(header_tmpl)))
        else:
            assert False, "Invalid byte in header: {!r}".format(byte)

    return result


def compile_print(args, context):
    assert len(args) == 1, "print takes exactly one argument"

    result = []
    result.extend(compile_expr(args[0], context))
    # TODO: we need the ability to get length of strings created at runtime.
    # TODO: this assumes the last argument was a string literal.
    if context['string_literals']:
        last_literal = list(context['string_literals'].keys())[-1]
        last_literal_len = len(last_literal)
    else:
        last_literal_len = 0

    result.extend(compile_string_check(context))

    # Previous expression is in rax, move to 2nd argument register.
    # mov rsi, rax
    result.extend([0x48, 0x89, 0xc6])

    result.extend([
        0xb8, 0x01, 0x00, 0x00, 0x00, # mov eax, 1 (1 = sys_write)
        0xbf, 0x01, 0x00, 0x00, 0x00, # mov edi, 1 (1 = stdout)
    ])

    # mov len(literal) %rdx
    result.extend([0x48, 0xba] + int_64bit(last_literal_len))
    # syscall
    result.extend([0x0f, 0x05])

    return result


def compile_int_literal(val):
    # mov VAL rax
    return [0x48, 0xb8] + int_64bit(val)


def compile_string_literal(value, context):
    # TODO: do this conversion during lexing.
    string_literal = bytes(value, 'ascii')

    offset = string_lit_offset(string_literal, context)
    # mov ADDR OF VAL rax
    return [0x48, 0xb8, ['string_lit', offset]]


def compile_int_check(context):
    error_msg = b"not an int :(\n"
    offset = string_lit_offset(error_msg, context)

    error_block = [
        0xb8, 0x01, 0x00, 0x00, 0x00, # mov eax, 1 (1 = sys_write)
        0xbf, 0x01, 0x00, 0x00, 0x00, # mov edi, 2 (2 = stderr)
    ]
    # mov rsi, STRING_LIT_ADDR
    error_block.extend([0x48, 0xbe, ['string_lit', offset]])
    # mov len(literal) %rdx
    error_block.extend([0x48, 0xba] + int_64bit(len(error_msg)))
    # syscall
    error_block.extend([0x0f, 0x05])
    
    result = []
    # We consider an integer to be an immediate less than 127.
    # TODO: proper value tagging scheme.
    # cmp rax, 127
    result.extend([0x48, 0x3d] + int_32bit(127))
    # jl END_OF_ERROR_BLOCK
    result.extend([0xf, 0x8c] + int_32bit(num_bytes(error_block)))

    result.extend(error_block)

    return result


def compile_string_check(context):
    error_msg = b"not a string :(\n"
    offset = string_lit_offset(error_msg, context)

    error_block = [
        0xb8, 0x01, 0x00, 0x00, 0x00, # mov eax, 1 (1 = sys_write)
        0xbf, 0x01, 0x00, 0x00, 0x00, # mov edi, 2 (2 = stderr)
    ]
    # mov rsi, STRING_LIT_ADDR
    error_block.extend([0x48, 0xbe, ['string_lit', offset]])
    # mov len(literal) %rdx
    error_block.extend([0x48, 0xba] + int_64bit(len(error_msg)))
    # syscall
    error_block.extend([0x0f, 0x05])
    
    result = []
    # We consider a string to be an immediate greater than 127.
    # TODO: proper value tagging scheme.
    # cmp rax, 127
    result.extend([0x48, 0x3d] + int_32bit(127))
    # jg END_OF_ERROR_BLOCK
    result.extend([0x0f, 0x8f] + int_32bit(num_bytes(error_block)))

    result.extend(error_block)

    return result


def compile_exit(args, context):
    assert len(args) == 1, "exit takes exactly one argument"

    result = []
    result.extend(compile_expr(args[0], context))

    result.extend(compile_int_check(context))
    
    # Previous expression is in rax, move to argument register.
    # mov rdi, rax
    result.extend([0x48, 0x89, 0xc7])

    result.extend([
        # mov $60 %eax (60 = sys_exit)
        0xb8, 0x3c, 0x00, 0x00, 0x00,
        # syscall
        0x0f, 0x05,
    ])

    return result


def compile_add(args, context):
    assert len(args) == 2, "+ takes exactly two arguments"

    result = []
    result.extend(compile_expr(args[0], context))
    result.extend(compile_int_check(context))
    # Push first argument, so we can reuse rax.
    # push rax
    result.extend([0x50])

    # Evaluate second argument, result in rax.
    result.extend(compile_expr(args[1], context))
    result.extend(compile_int_check(context))

    # pop rdi
    result.extend([0x5f])

    # add rax, rdi
    result.extend([0x48, 0x01, 0xf8])
    
    return result


def compile_expr(subtree, context):
    kind, value = subtree
    if kind == LIST:
        # function call
        assert value, "Function calls require a function name (got an empty list)"

        (fun_kind, fun_name) = value[0]
        assert fun_kind == SYMBOL, "Can only call symbol names, got {}".format(fun_kind)

        args = value[1:]
        if fun_name == 'print':
            return compile_print(args, context)
        elif fun_name == 'exit':
            return compile_exit(args, context)
        elif fun_name == '+':
            return compile_add(args, context)
        else:
            assert False, "Unknown function: {}".format(fun_name)
    elif kind == INTEGER:
        return compile_int_literal(value)
    elif kind == STRING:
        return compile_string_literal(value, context)
    else:
        assert False, "Expected function call, got {}".format(kind)


def compile_main(ast, context):
    # The raw bytes of the instructions for the main function.
    main_fun_tmpl = []

    for subtree in ast:
        main_fun_tmpl.extend(compile_expr(subtree, context))

    # Always end the main function with (exit 0) if the user hasn't
    # exited. Otherwise, we continue executing into the data section and segfault.
    main_fun_tmpl.extend(compile_exit([(INTEGER, 0)], context))

    result = []
    for byte in main_fun_tmpl:
        if isinstance(byte, int):
            result.append(byte)
        elif isinstance(byte, list) and len(byte) == 2 and byte[0] == 'string_lit':
            offset = byte[1]

            header_size = 120 # TODO: compute
            # String literals are immediately after code section.
            result.extend(int_64bit(ENTRY_POINT + header_size + num_bytes(main_fun_tmpl) + offset))
        else:
            assert False, "Invalid template in main fun: {!r}".format(byte)

    return result


def string_lit_offset(value, context):
    """Add `value` to context, and return its offset.

    """
    assert isinstance(value, bytes), "String literals must be bytes"

    # If we've seen this string literal before, reuse the previous offset.
    if value in context['string_literals']:
        return context['string_literals'][value]

    # Remember this new string literal, and compute its offset.
    offset = context['data_offset']
    context['string_literals'][value] = offset
    context['data_offset'] += len(value)

    return offset



def main(filename):
    with open(filename) as f:
        src = f.read()

    tokens = list(lex(src))
    ast = parse(tokens)

    context = {'string_literals': {}, 'data_offset': 0}

    main_fun = compile_main(ast, context)
    header = elf_header_instructions(main_fun, context)

    with open('hello', 'wb') as f:
        f.write(bytes(header))
        f.write(bytes(main_fun))
        # TODO: put string literals in a named section
        # Assumes dict is in insertion order (Python 3.6+)
        for string_literal in context['string_literals'].keys():
            f.write(string_literal)

    os.chmod('hello', 0o744)

    print("Wrote hello ELF")


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: {} <path>".format(sys.argv[0]))
        sys.exit(1)
    
    main(sys.argv[1])
