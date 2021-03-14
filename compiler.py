#!/usr/bin/env python

import os
import sys
import string


STRING = "STRING"
INTEGER = "INTEGER"
BOOLEAN = "BOOLEAN"
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
            elif string_lit[i + 1] == '"':
                res = res + '"'
                i += 2
            elif string_lit[i + 1] == "\\":
                res = res + "\\"
                i += 2
            else:
                assert False, "Invalid escape sequence: \\{}".format(string_lit[i + 1])
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
        elif c in string.ascii_letters or c in string.digits or c in ['!', '?', '+', '-', '<', '>', '=', '*']:
            if token is None:
                token = c
            else:
                token = token + c
            i += 1
        elif c == '"':
            end_i = i + 1
            while end_i < len(src) and src[end_i] != '"':
                if src[end_i] == '\\':
                    end_i += 2
                else:
                    end_i += 1

            assert src[end_i] == '"'
            yield src[i:end_i + 1]
            i = end_i + 1
        else:
            assert False, "Could not lex: {!r}".format(src[i:])


def is_int_literal(token):
    return token[0] in string.digits


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
    elif token == 'true':
        return (i + 1, (BOOLEAN, True))
    elif token == 'false':
        return (i + 1, (BOOLEAN, False))
    elif token.startswith('"'):
        # string literal
        return (i + 1, (STRING, unescape(token)))
    elif is_int_literal(token):
        return (i + 1, (INTEGER, parse_int(token)))
    else:
        # symbol
        return (i + 1, (SYMBOL, token))

def parse_int(token):
    """Convert a token of a integer literal to its integer value.

    >>> parse_int("100")
    100
    >>> parse_int("0xA")
    10

    """
    if token.startswith('0x'):
        return int(token, base=16)
    elif token.startswith('0o'):
        return int(token, base=8)
    else:
        return int(token)


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


def signed_int_64bit(num):
    """Return `num` as a list of bytes of its 64-bit signed
    representation.

    """
    return list(num.to_bytes(8, 'little', signed=True))


def int_32bit(num):
    """Return `num` as a list of bytes of its 32-bit representation.

    """
    return list(num.to_bytes(4, 'little', signed=True))

# TAGGING SCHEME
#
# We use the top bits to tag the runtime type, leaving the rest
# for content.
#
TAG_BITS = 3

INTEGER_TAG_BITS = 0b000
STRING_TAG_BITS = 0b100
BOOLEAN_TAG_BITS = 0b110

BOOLEAN_TAG_BYTE = (BOOLEAN_TAG_BITS << (8 - TAG_BITS))
BOOLEAN_TAG = BOOLEAN_TAG_BYTE << (8 * 7)

STRING_TAG_BYTE = (STRING_TAG_BITS << (8 - TAG_BITS))
STRING_TAG = STRING_TAG_BYTE << (8 * 7)



def zero_rax_tag_bits():
    """Set the tag bits to zero in register rax.

    """
    result = []
    # shl rax, TAG_BITS
    result.extend([0x48, 0xC1, 0xE0, TAG_BITS])
    # shr rax, TAG_BITS
    result.extend([0x48, 0xC1, 0xE8, TAG_BITS])

    return result


def compile_to_tagged_int():
    """Emit instructions that convert a 64-bit integer value to a tagged
    value.

    Overflows wrap around.

    """
    return zero_rax_tag_bits()


def compile_from_tagged_int():
    """Emit instructions that convert a tagged
    integer to a 64-bit integer.

    """
    # Since the tag bits are zero, no work required here.
    return []


def compile_ptr_to_tagged_string():
    # Compile a pointer to a string object (in rodata) to a tagged
    # pointer.

    result = []

    # TODO: how can we be sure that real string pointers don't have
    # the tag bits set?

    # mov rdi, STRING_TAG
    result.extend([0x48, 0xbf] + int_64bit(STRING_TAG))
    # add rax, rdi
    result.extend([0x48, 0x01, 0xf8])

    return result


def compile_tagged_string_to_ptr():
    return zero_rax_tag_bits()


def compile_allocate(args, context):
    assert len(args) == 1, "allocate requires one argument"

    result = []
    result.extend(compile_expr(args[0], context))
    result.extend(compile_int_check(context))
    
    # mov rsi, rax (num bytes in rsi, from argument)
    result.extend([0x48, 0x89, 0xC6])

    # call mmap, which is syscall 9
    # mov rax, 9
    result.extend([0x48, 0xb8] + int_64bit(9))

    # mov rdi, 0 (address)
    result.extend([0x48, 0xbf] + int_64bit(0))

    # mov rdx, $protect (read | write)
    read_write = 0x1 | 0x2
    result.extend([0x48, 0xba] + int_64bit(read_write))

    # mov r10, $flags MAP_ANONYMOUS
    map_anonymous = 0x20
    map_private = 0x02
    result.extend([0x49, 0xba] + int_64bit(map_anonymous | map_private))

    # mov r8, -1 (file descriptor)
    result.extend([0x49, 0xb8] + signed_int_64bit(-1))

    # mov r9, $offset
    result.extend([0x49, 0xb9] + int_64bit(0))

    # syscall
    result.extend([0x0f, 0x05])

    return result


def num_bytes(byte_tmpl):
    """Given a list of raw bytes and template strings, calculate the total number
    of bytes that the final output will have.

    Assumes all template strings are replaced by 8 bytes.

    >>> num_bytes([0x127, "prog_bytes"])
    9

    """
    total = 0
    for b in byte_tmpl:
        if isinstance(b, int):
            total += 1
        elif isinstance(b, list) and b:
            tmpl_key = b[0]
            if tmpl_key == 'string_lit':
                total += 8
            elif tmpl_key == 'fun_offset':
                total += 4
            else:
                assert False, "tmpl key: {!r}".format(tmpl_key)
        elif b in ('prog_entry', 'prog_length'):
            total += 8
        else:
            assert False, "tmpl: {!r}".format(b)

    return total


def elf_header_instructions(funs_instrs, string_literals):
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

    rodata_size = sum(num_bytes_string_lit(lit) for lit in string_literals)
    prog_length = num_bytes(header_tmpl) + len(funs_instrs) + rodata_size

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

    result.extend(compile_string_check(context))

    # Save the value, so we can restore it after the syscall.
    # push rax
    result.extend([0x50])
    
    result.extend(compile_tagged_string_to_ptr())

    # TODO: we need the ability to get length of strings created at runtime.
    # The first 8 bytes of a string store the length, so copy it to rdx.
    # mov rdx, [rax]
    result.extend([0x48, 0x8B, 0x10])

    # After those bytes, we have the string data itself.
    # add rax, 8
    result.extend([0x48, 0x05] + int_32bit(8))

    # Previous expression is in rax, move to 2nd argument register.
    # mov rsi, rax
    result.extend([0x48, 0x89, 0xc6])

    result.extend([
        0xb8, 0x01, 0x00, 0x00, 0x00, # mov eax, 1 (1 = sys_write)
        0xbf, 0x01, 0x00, 0x00, 0x00, # mov edi, 1 (1 = stdout)
    ])

    # syscall
    result.extend([0x0f, 0x05])

    # Use the argument as the return value.
    # TODO: define a null type.
    # pop rax
    result.extend([0x58])

    return result


def compile_string_length(args, context):
    assert len(args) == 1, "string-length takes exactly one argument"

    result = []
    result.extend(compile_expr(args[0], context))

    result.extend(compile_string_check(context))
    result.extend(compile_tagged_string_to_ptr())

    # The first 8 bytes of a string store the length, so copy it to rax.
    # mov rax, [rax]
    result.extend([0x48, 0x8B, 0x00])

    result.extend(compile_to_tagged_int())

    return result


def compile_error(args, context):
    assert len(args) == 1, "error takes exactly one argument"

    result = []
    result.extend(compile_expr(args[0], context))

    result.extend(compile_string_check(context))
    result.extend(compile_tagged_string_to_ptr())

    # The first 8 bytes of a string store the length, so copy it to rdi.
    # mov rdx, [rax]
    result.extend([0x48, 0x8B, 0x10])

    # Get the pointer to the string data in rsi.
    # add rax, 8
    result.extend([0x48, 0x05] + int_32bit(8))
    # mov rsi, rax
    result.extend([0x48, 0x89, 0xC6])

    # mov eax, 1 (1 = sys_write)
    result.extend([0xb8] + int_32bit(1))
        
    # mov edi, 2 (2 = stderr)
    result.extend([0xbf] + int_32bit(2))
    
    # syscall
    result.extend([0x0f, 0x05])

    # mov rdi, 1 (exit code)
    result.extend([0x48, 0xbf] + int_64bit(1))
    result.extend([
        # mov eax, 60 (60 = sys_exit)
        0xb8, 0x3c, 0x00, 0x00, 0x00,
        # syscall
        0x0f, 0x05])

    return result


def compile_not(args, context):
    assert len(args) == 1, "not takes exactly one argument"

    result = []
    result.extend(compile_expr(args[0], context))
    result.extend(compile_bool_check(context))

    # toggle the top bit.
    # btc rax, 0
    result.extend([0x48, 0x0F, 0xBA, 0xF8, 0x00])

    return result

def local_var_offset(var, context):
    """Add `var` to `context`, and return its offset to rbp.

    """
    kind, var_name = var
    assert kind == SYMBOL, "Expected a symbol, got {!r}".format(kind)

    # If we've seen this variable name before, reuse the previous offset.
    if var_name in context['locals']:
        return context['locals'][var_name]

    # Remember this new local variable, and compute its offset. Each
    # local variable is one word (64 bits), and is at a lower memory
    # address than rbp.
    offset = -1 * (len(context['locals']) + 1) * 8
    context['locals'][var_name] = offset

    return offset


def compile_local_variable(var_name, context):
    assert isinstance(var_name, str)

    offset = None
    if var_name in context['arg_offsets']:
        offset = context['arg_offsets'][var_name]
    # Locals variables can shadow function parameters.
    if var_name in context['locals']:
        offset = context['locals'][var_name]

    if offset is None:
        assert False, "Variable `{}` is not bound".format(var_name)

    result = []
    # mov rax, [rbp + offset]
    result.extend([0x48, 0x8B, 0x85] + int_32bit(offset))
    return result


def compile_let(args, context):
    assert len(args) >= 2, "let takes at least two arguments"

    vars_and_exprs = args[0]
    assert vars_and_exprs[0] == LIST, "Expected a list of variables and their values."
    vars_and_exprs = vars_and_exprs[1]

    assert len(vars_and_exprs) % 2 == 0, "Expected a list of variables and their values (got an odd list)"
    vars = vars_and_exprs[::2]
    exprs = vars_and_exprs[1::2]
    unique_vars = set(vars)

    result = []
    # Each local variable is one word (64 bits).
    # sub rsp, 8 * len(vars)
    result.extend([0x48, 0x81, 0xEC] + int_32bit(8 * len(unique_vars)))

    old_locals = context['locals'].copy()

    for var, expr in zip(vars, exprs):
        result.extend(compile_expr(expr, context))

        # Store the value on the stack.
        offset = local_var_offset(var, context)
        # mov [rbp + offset], rax
        result.extend([0x48, 0x89, 0x85] + int_32bit(offset))

    for expr in args[1:]:
        result.extend(compile_expr(expr, context))

    # add rsp, 8 * len(vars)
    result.extend([0x48, 0x81, 0xC4] + int_32bit(8 * len(vars)))

    # Restore previous locals.
    context['locals'] = old_locals
    
    return result


def compile_set(args, context):
    assert len(args) == 2, "set! takes two arguments"

    var = args[0]
    assert var[0] == SYMBOL, "Expected a symbol to assign to"
    var_name = var[1]
    assert var_name in context['locals'], "Variable `{}` is not bound".format(var_name)

    result = []

    result.extend(compile_expr(args[1], context))
    
    # mov [rbp + offset], rax
    result.extend([0x48, 0x89, 0x85] + int_32bit(context['locals'][var_name]))

    # TODO: once we have null, set! should return null.
    
    return result


def compile_while(args, context):
    """
    WHILE_START:
      eval arg[0]
      cmp rax, 0
      je WHILE_END
      eval arg[1]
      jmp WHILE_START
    WHILE_END:
      mov rax, TAGGED_ZERO
    """
    assert len(args) == 2, "while takes two arguments"

    loop_header = []
    loop_header.extend(compile_expr(args[0], context))
    loop_header.extend(compile_bool_check(context))

    loop_header.extend(zero_rax_tag_bits())
    # cmp rax, 0
    loop_header.extend([0x48, 0x3d] + int_32bit(0))

    # eval body
    loop_body = compile_expr(args[1], context)

    # TODO: currently num_bytes assumes that all placeholders are 8
    # bytes, so we can't use it with jumps with 4 byte offsets.
    je_num_bytes = 6
    jmp_num_bytes = 5
    result_bytes = num_bytes(loop_header) + je_num_bytes + num_bytes(loop_body) + jmp_num_bytes

    result = []
    result.extend(loop_header)
    while_end = num_bytes(loop_body) + jmp_num_bytes
    # jmp while_end
    result.extend([0x0f, 0x84] + int_32bit(while_end))

    result.extend(loop_body)
    
    # jmp WHILE_START
    result.extend([0xe9] + int_32bit(-1 * result_bytes))

    # We need to return a legal value, so arbitrarily choose 0.
    result.extend(compile_int_literal(0))

    return result


def compile_if(args, context):
    assert len(args) == 3, "if takes exactly three arguments"

    result = []
    result.extend(compile_expr(args[0], context))
    result.extend(compile_bool_check(context))

    true_block = compile_expr(args[1], context)
    false_block = compile_expr(args[2], context)

    # jmp END_OF_TRUE_BLOCk
    false_block.extend([0xe9] + int_32bit(num_bytes(true_block)))

    result.extend(zero_rax_tag_bits())
    # cmp rax, 1
    result.extend([0x48, 0x3d] + int_32bit(1))
    # je TRUE_BLOCK (straight after FALSE_BLOCK)
    result.extend([0x0f, 0x84] + int_32bit(num_bytes(false_block)))

    result.extend(false_block)
    result.extend(true_block)

    return result


def compile_do(args, context):
    assert len(args) > 0, "do requires at least one argument"

    result = []
    for arg in args:
        result.extend(compile_expr(arg, context))

    return result


def compile_equals(args, context):
    assert len(args) == 2, "= requires two arguments"

    result = []
    result.extend(compile_expr(args[0], context))
    
    # Push first argument, so we can reuse rax.
    # push rax
    result.extend([0x50])

    # Evaluate second argument, result in rax.
    result.extend(compile_expr(args[1], context))

    # pop rdi
    result.extend([0x5f])

    # cmp rdi, rax
    result.extend([0x48, 0x39, 0xC7])

    # write 0x00 or 0x01 to the low byte of rax.
    # sete al
    result.extend([0x0F, 0x94, 0xC0])

    # zero the upper three bytes of rax
    # shl rax, 64 - 8
    result.extend([0x48, 0xC1, 0xE0, 64-8])
    # shr rax, 64 - 8
    result.extend([0x48, 0xC1, 0xE8, 64-8])

    # Set the boolean tag
    # mov rdi, BOOLEAN_TAG
    result.extend([0x48, 0xbf] + int_64bit(BOOLEAN_TAG))

    # add rax, rdi
    result.extend([0x48, 0x01, 0xF8])
    
    return result


def compile_less_than(args, context):
    assert len(args) == 2, "< requires two arguments"

    result = []
    result.extend(compile_expr(args[0], context))
    result.extend(compile_int_check(context))
    # untag
    result.extend(compile_from_tagged_int())
    
    # Push first argument, so we can reuse rax.
    # push rax
    result.extend([0x50])

    # Evaluate second argument, result in rax.
    result.extend(compile_expr(args[1], context))
    result.extend(compile_int_check(context))
    # untag
    result.extend(compile_from_tagged_int())

    # pop rdi
    result.extend([0x5f])

    # cmp rdi, rax
    result.extend([0x48, 0x39, 0xC7])

    # A value is less if Sign Flag != Overflow Flag
    # (this is what the jl instruction does).

    # write 0x00 or 0x01 to the low byte of rax.
    # setl al
    result.extend([0x0F, 0x9C, 0xC0])

    # zero the upper three bytes of rax
    # shl rax, 64 - 8
    result.extend([0x48, 0xC1, 0xE0, 64-8])
    # shr rax, 64 - 8
    result.extend([0x48, 0xC1, 0xE8, 64-8])

    # Set the boolean tag
    # mov rdi, BOOLEAN_TAG
    result.extend([0x48, 0xbf] + int_64bit(BOOLEAN_TAG))

    # add rax, rdi
    result.extend([0x48, 0x01, 0xF8])
    
    return result


def compile_greater_than(args, context):
    assert len(args) == 2, "> requires two arguments"

    result = []
    result.extend(compile_expr(args[0], context))
    result.extend(compile_int_check(context))
    # untag
    result.extend(compile_from_tagged_int())
    
    # Push first argument, so we can reuse rax.
    # push rax
    result.extend([0x50])

    # Evaluate second argument, result in rax.
    result.extend(compile_expr(args[1], context))
    result.extend(compile_int_check(context))
    # untag
    result.extend(compile_from_tagged_int())

    # pop rdi
    result.extend([0x5f])

    # cmp rdi, rax
    result.extend([0x48, 0x39, 0xC7])

    # write 0x00 or 0x01 to the low byte of rax.
    # setg al
    result.extend([0x0F, 0x9F, 0xC0])

    # zero the upper three bytes of rax
    # shl rax, 64 - 8
    result.extend([0x48, 0xC1, 0xE0, 64-8])
    # shr rax, 64 - 8
    result.extend([0x48, 0xC1, 0xE8, 64-8])

    # Set the boolean tag
    # mov rdi, BOOLEAN_TAG
    result.extend([0x48, 0xbf] + int_64bit(BOOLEAN_TAG))

    # add rax, rdi
    result.extend([0x48, 0x01, 0xF8])
    
    return result


def compile_int_literal(val):
    result = []
    # mov rax, VAL
    result.extend([0x48, 0xb8] + int_64bit(val))

    result.extend(compile_to_tagged_int())
    return result


def compile_string_literal(value, context):
    # TODO: do this conversion during lexing.
    string_literal = bytes(value, 'ascii')

    offset = string_lit_offset(string_literal, context)

    result = []
    # mov ADDR OF VAL rax
    result.extend([0x48, 0xb8, ['string_lit', offset]])

    result.extend(compile_ptr_to_tagged_string())
    return result


def compile_bool_literal(value):
    if value:
        # mov rax, (BOOLEAN_TAG | 1)
        return [0x48, 0xb8] + int_64bit(BOOLEAN_TAG | 1)
    else:
        # mov rax, (BOOLEAN_TAG | 0)
        return [0x48, 0xb8] + int_64bit(BOOLEAN_TAG)


def compile_int_check(context):
    """Throw a runtime error if the value in rax is not an integer.
    Does not modify rax.

    """
    error_block = compile_die(b"not an int :(\n", context)

    result = []
    # A value is an integer if the top two bits are 0b00.
    # mov rdi, rax
    result.extend([0x48, 0x89, 0xc7])

    # shr rdi, 64 - TAG_BITS
    result.extend([0x48, 0xc1, 0xef, 64 - TAG_BITS])
    # cmp rdi, 0
    result.extend([0x48, 0x81, 0xff] + int_32bit(0))
    # je END_OF_ERROR_BLOCK
    result.extend([0x0f, 0x84] + int_32bit(num_bytes(error_block)))

    result.extend(error_block)
    return result

def compile_die(message, context):
    assert isinstance(message, bytes)
    
    addr = string_lit_offset(message, context)

    result = [
        # mov eax, 1 (1 = sys_write)
        0xb8, 0x01, 0x00, 0x00, 0x00,
    ]
    # mov edi, 2 (2 = stderr)
    result.extend([0xbf] + int_32bit(2))
    # mov rsi, STRING_LIT_ADDR
    result.extend([0x48, 0xbe, ['string_lit', addr]])

    # The first 8 bytes of a string store the length.
    # add rsi, 8
    result.extend([0x48, 0x81, 0xc6] + int_32bit(8))

    # mov rdx, len(literal)
    result.extend([0x48, 0xba] + int_64bit(len(message)))
    # syscall
    result.extend([0x0f, 0x05])

    # mov rdi, 1 (exit code)
    result.extend([0x48, 0xbf] + int_64bit(1))
    result.extend([
        # mov eax, 60 (60 = sys_exit)
        0xb8, 0x3c, 0x00, 0x00, 0x00,
        # syscall
        0x0f, 0x05])

    return result


def compile_string_check(context):
    error_block = compile_die(b"not a string :(\n", context)

    result = []
    # A value is a string if the top three bits are 0b100.
    # mov rdi, rax
    result.extend([0x48, 0x89, 0xc7])
    # shr rdi, 64 - TAG_BITS
    result.extend([0x48, 0xc1, 0xef, 64 - TAG_BITS])
    # cmp rdi, 4
    result.extend([0x48, 0x81, 0xff] + int_32bit(0b100))
    # je END_OF_ERROR_BLOCK
    result.extend([0x0f, 0x84] + int_32bit(num_bytes(error_block)))
    
    result.extend(error_block)
    return result


def compile_bool_check(context):
    error_block = compile_die(b"not a bool :(\n", context)

    result = []
    # A value is a bool if the top three bits are 0b110.
    # mov rdi, rax
    result.extend([0x48, 0x89, 0xc7])
    # shr rdi, 64 - TAG_BITS
    result.extend([0x48, 0xc1, 0xef, 64 - TAG_BITS])
    # cmp rdi, 6
    result.extend([0x48, 0x81, 0xff] + int_32bit(0b110))
    # je END_OF_ERROR_BLOCK
    result.extend([0x0f, 0x84] + int_32bit(num_bytes(error_block)))
    
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


def compile_file_exists(args, context):
    assert len(args) == 1, "file-exists? takes exactly one argument"

    result = []
    result.extend(compile_expr(args[0], context))
    result.extend(compile_string_check(context))
    
    result.extend(compile_tagged_string_to_ptr())

    # String data starts with the size, then the string data
    # itself. Strings are already null-terminated.
    # add rax, 8
    result.extend([0x48, 0x05] + int_32bit(8))

    # Previous expression is in rax, move to 1st argument register.
    # mov rdi, rax
    result.extend([0x48, 0x89, 0xC7])

    # From unistd.h.
    f_ok = 0
    # mov rsi, flag
    result.extend([0x48, 0xBE] + int_64bit(f_ok))

    # mov rax, 21 (access)
    result.extend([0x48, 0xb8] + int_64bit(21))

    # syscall
    result.extend([0x0f, 0x05])

    # We get 0 in rax if the file exists.
    # cmp rax, 0
    result.extend([0x48, 0x3d] + int_32bit(0))

    # write 0x00 or 0x01 to the low byte of rax.
    # sete al
    result.extend([0x0F, 0x94, 0xC0])

    # zero the upper three bytes of rax
    # shl rax, 64 - 8
    result.extend([0x48, 0xC1, 0xE0, 64-8])
    # shr rax, 64 - 8
    result.extend([0x48, 0xC1, 0xE8, 64-8])

    # set boolean tag.
    # mov rdi, BOOLEAN_TAG
    result.extend([0x48, 0xBF] + int_64bit(BOOLEAN_TAG))
    # add rax, rdi
    result.extend([0x48, 0x01, 0xF8])

    return result


def compile_open(args, context):
    assert len(args) == 1, "open takes exactly one argument"

    result = []
    result.extend(compile_expr(args[0], context))
    result.extend(compile_string_check(context))
    
    result.extend(compile_tagged_string_to_ptr())

    # String data starts with the size, then the string data
    # itself. Strings are already null-terminated.
    # add rax, 8
    result.extend([0x48, 0x05] + int_32bit(8))

    # Previous expression is in rax, move to 1st argument register.
    # mov rdi, rax
    result.extend([0x48, 0x89, 0xC7])

    # https://github.com/torvalds/linux/blob/master/include/uapi/asm-generic/fcntl.h
    o_wronly = 0o1
    o_creat = 0o100
    # mov rsi, flag
    result.extend([0x48, 0xBE] + int_64bit(o_wronly | o_creat))

    mode = 0o644
    # mov rdx, mode
    result.extend([0x48, 0xBA] + int_64bit(mode))
    
    # mov eax, 2 (2 = sys_open)
    result.extend([0xb8, 0x02, 0x00, 0x00, 0x00])

    # syscall
    result.extend([0x0f, 0x05])

    # TODO: error if we get a negative file descriptor.

    # We get a file descriptor, tag as an integer.
    result.extend(compile_to_tagged_int())

    return result


def compile_delete(args, context):
    assert len(args) == 1, "delete! takes exactly one argument"

    result = []
    result.extend(compile_expr(args[0], context))
    result.extend(compile_string_check(context))
    
    result.extend(compile_tagged_string_to_ptr())

    # String data starts with the size, then the string data
    # itself. Strings are already null-terminated.
    # add rax, 8
    result.extend([0x48, 0x05] + int_32bit(8))

    # Previous expression is in rax, move to 1st argument register.
    # mov rdi, rax
    result.extend([0x48, 0x89, 0xC7])

    # mov rax, 87 (unlink syscall)
    result.extend([0x48, 0xb8] + int_64bit(87))

    # syscall
    result.extend([0x0f, 0x05])

    # TODO: error if we couldn't delete it.

    # We need to return a legal value, so arbitrarily choose 0.
    result.extend(compile_int_literal(0))

    return result


def compile_write(args, context):
    assert len(args) == 2, "write! requires two arguments"

    result = []
    result.extend(compile_expr(args[0], context))
    result.extend(compile_int_check(context))
    
    # Previous expression is in rax, save it in rcx.
    # mov rcx, rax
    result.extend([0x48, 0x89, 0xC1])

    # TODO: we should check that the value is <128.
    result.extend(compile_expr(args[1], context))
    result.extend(compile_int_check(context))

    # We need the byte in memory, so we can pass a pointer.
    # push rax
    result.extend([0x50])

    # rsp now points to the byte we want to write.
    # mov rsi, rsp
    result.extend([0x48, 0x89, 0xE6])

    # We saved the file descriptor we wanted in rcx, move to 1st
    # argument register.
    # mov rdi, rcx
    result.extend([0x48, 0x89, 0xCF])

    # We're only writing one byte.
    # mov rdx, 1
    result.extend([0x48, 0xBA] + int_64bit(1))

    # 1 = sys_write
    # mov rax, 1
    result.extend([0x48, 0xB8] + int_64bit(1))

    # syscall
    result.extend([0x0f, 0x05])

    # Clean up stack.
    # This also means we're arbitrarily returning the second argument,
    # because we dont have a null type yet.
    # pop rax
    result.extend([0x58])

    return result


def compile_chmod(args, context):
    assert len(args) == 2, "chmod! requires two arguments"

    result = []
    result.extend(compile_expr(args[0], context))
    result.extend(compile_string_check(context))

    result.extend(compile_tagged_string_to_ptr())
    # add rax, 8
    result.extend([0x48, 0x05] + int_32bit(8))

    # push rax
    result.extend([0x50])
    
    # First syscall argument in RDI.

    result.extend(compile_expr(args[1], context))
    result.extend(compile_int_check(context))
    result.extend(compile_from_tagged_int())

    # First syscall argument in RDI.
    # pop rdi
    result.extend([0x5f])

    # Second syscall argument in RSI.
    # mov rsi, rax
    result.extend([0x48, 0x89, 0xc6])

    # chmod has syscall number 90.
    # mov rax, 90
    result.extend([0x48, 0xb8] + int_64bit(90))

    # syscall
    result.extend([0x0f, 0x05])

    # Arbitrarily return zero since we don't have null yet.
    result.extend(compile_int_literal(0))

    return result


def compile_seek_end(args, context):
    assert len(args) == 1, "seek-end! requires 1 argument"

    result = []
    result.extend(compile_expr(args[0], context))
    result.extend(compile_int_check(context))
    result.extend(compile_from_tagged_int())

    # RDI contains the file descriptor for this syscall.
    # mov rdi, rax
    result.extend([0x48, 0x89, 0xC7])

    # mov rax, 8 (lseek)
    result.extend([0x48, 0xb8] + int_64bit(8))

    # Offset of zero from the end.
    # mov rsi, 0
    result.extend([0x48, 0xBE] + int_64bit(0))

    # Whence is SEEK_END (2 according to unistd.h).
    # mov rdx, 2
    result.extend([0x48, 0xBA] + int_64bit(2))
    
    # syscall
    result.extend([0x0f, 0x05])

    # TODO: handle lseek errors.

    # Return the number of bytes seeked.
    result.extend(compile_to_tagged_int())

    return result


def compile_add(args, context):
    assert len(args) == 2, "+ takes exactly two arguments"

    result = []
    result.extend(compile_expr(args[0], context))
    result.extend(compile_int_check(context))
    # untag
    result.extend(compile_from_tagged_int())
    
    # Push first argument, so we can reuse rax.
    # push rax
    result.extend([0x50])

    # Evaluate second argument, result in rax.
    result.extend(compile_expr(args[1], context))
    result.extend(compile_int_check(context))
    # untag
    result.extend(compile_from_tagged_int())

    # pop rdi
    result.extend([0x5f])

    # add rax, rdi
    result.extend([0x48, 0x01, 0xf8])
    result.extend(compile_to_tagged_int())
    
    return result


def compile_subtract(args, context):
    assert len(args) == 2, "- takes exactly two arguments"

    result = []
    result.extend(compile_expr(args[0], context))
    result.extend(compile_int_check(context))
    # untag
    result.extend(compile_from_tagged_int())
    
    # Push first argument, so we can reuse rax.
    # push rax
    result.extend([0x50])

    # Evaluate second argument, result in rax.
    result.extend(compile_expr(args[1], context))
    result.extend(compile_int_check(context))
    # untag
    result.extend(compile_from_tagged_int())

    # mov rdi, rax
    result.extend([0x48, 0x89, 0xC7])

    # pop rax
    result.extend([0x58])

    # sub rax, rdi
    result.extend([0x48, 0x29, 0xF8])
    result.extend(compile_to_tagged_int())
    
    return result


def compile_multiply(args, context):
    assert len(args) == 2, "* takes exactly two arguments"

    result = []
    result.extend(compile_expr(args[0], context))
    result.extend(compile_int_check(context))
    # untag
    result.extend(compile_from_tagged_int())
    
    # Push first argument, so we can reuse rax.
    # push rax
    result.extend([0x50])

    # Evaluate second argument, result in rax.
    result.extend(compile_expr(args[1], context))
    result.extend(compile_int_check(context))
    # untag
    result.extend(compile_from_tagged_int())

    # pop rdi
    result.extend([0x5f])

    # imul rax, rdi
    result.extend([0x48, 0x0F, 0xAF, 0xC7])
    result.extend(compile_to_tagged_int())
    
    return result


def compile_intdiv(args, context):
    # TODO: handle division by zero.
    assert len(args) == 2, "intdiv takes exactly two arguments"

    result = []
    result.extend(compile_expr(args[0], context))
    result.extend(compile_int_check(context))
    # untag
    result.extend(compile_from_tagged_int())
    
    # Push first argument, so we can reuse rax.
    # push rax
    result.extend([0x50])

    # Evaluate second argument, result in RAX.
    result.extend(compile_expr(args[1], context))
    result.extend(compile_int_check(context))
    # untag
    result.extend(compile_from_tagged_int())

    # put the second argument in RDI.
    # mov rdi, rax
    result.extend([0x48, 0x89, 0xC7])

    # pop rax
    result.extend([0x58])

    # DIV uses RDX:RAX as its source, so ensure RDX is zero.
    # mov rdx, 0
    result.extend([0x48, 0xBA] + int_64bit(0))

    # div rdi
    result.extend([0x48, 0xF7, 0xF7])
    # The quotient is in rax, so tag it and we're done.
    result.extend(compile_to_tagged_int())
    
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
        elif fun_name == '-':
            return compile_subtract(args, context)
        elif fun_name == '*':
            return compile_multiply(args, context)
        elif fun_name == 'intdiv':
            return compile_intdiv(args, context)
        elif fun_name == 'not':
            return compile_not(args, context)
        elif fun_name == 'if':
            return compile_if(args, context)
        elif fun_name == 'string-length':
            return compile_string_length(args, context)
        elif fun_name == 'let':
            return compile_let(args, context)
        elif fun_name == 'set!':
            return compile_set(args, context)
        elif fun_name == 'while':
            return compile_while(args, context)
        elif fun_name == 'do':
            return compile_do(args, context)
        elif fun_name == '<':
            return compile_less_than(args, context)
        elif fun_name == '>':
            return compile_greater_than(args, context)
        elif fun_name == '=':
            return compile_equals(args, context)
        elif fun_name == 'file-exists?':
            return compile_file_exists(args, context)
        elif fun_name == 'open':
            return compile_open(args, context)
        elif fun_name == 'write!':
            return compile_write(args, context)
        elif fun_name == 'delete!':
            return compile_delete(args, context)
        elif fun_name == 'chmod!':
            return compile_chmod(args, context)
        elif fun_name == 'seek-end!':
            return compile_seek_end(args, context)
        elif fun_name == 'error':
            return compile_error(args, context)
        elif fun_name == 'allocate':
            return compile_allocate(args, context)
        else:
            return compile_call(fun_name, args, context)
    elif kind == INTEGER:
        return compile_int_literal(value)
    elif kind == STRING:
        return compile_string_literal(value, context)
    elif kind == BOOLEAN:
        return compile_bool_literal(value)
    elif kind == SYMBOL:
        return compile_local_variable(value, context)
    else:
        assert False, "Expected function call, got {}".format(kind)


def num_args(fun_name, context):
    def_kind, def_value = context['global_funs'][fun_name]
    assert def_kind == LIST, "Malformed function definition"
    assert len(def_value) > 3, "defun requires a name, parameters, and a body"

    params_kind, params_value = def_value[2]
    assert params_kind == LIST, "Malformed function parameters"

    return len(params_value)


def compile_call(fun_name, args, context):
    assert fun_name in context['global_funs'], "Unknown function: {}".format(fun_name)

    expected_args = num_args(fun_name, context)
    err_msg = "Expected {} arguments to {}, got {}".format(expected_args, fun_name, len(args))
    assert expected_args == len(args), err_msg

    result = []

    # Push arguments right-to-left, following the System V AMD64 ABI.
    # TODO: Pass the first args in RDI, RSI, RDX, RCX, R8 and R9.

    for arg in reversed(args):
        result.extend(compile_expr(arg, context))

        # push rax
        result.extend([0x50])
    
    # CALL opcode
    result.extend([0xE8])

    # We may not know the offset of the function yet.
    result.extend([['fun_offset', fun_name]])

    # add rsp, 8 * len(args)
    result.extend([0x48, 0x81, 0xC4] + int_32bit(8 * len(args)))

    return result


def compile_start(context):
    """Call the main function, then exit.

    """
    result = []

    # Ensure rbp is set correctly, so we can return from main.
    # mov rbp, rsp
    result.extend([0x48, 0x89, 0xE5])

    result.extend(compile_call('main', [], context))

    # Always end execution with (exit 0) if the user hasn't exited.
    result.extend(compile_exit([(INTEGER, 0)], context))

    context['instr_bytes'] += num_bytes(result)
    return result


def compile_fun(ast, context):
    # Set up context items that are per-function.
    context['locals'] = {}
    
    ast_kind, ast_value = ast
    assert ast_kind == LIST

    defun = ast_value[0]
    assert defun == (SYMBOL, 'defun'), "Expected a function definition, got: {!r}".format(defun)
    name_kind, name = ast_value[1]
    assert name_kind == SYMBOL, "Function name must be a symbol."

    context['fun_offsets'][name] = context['instr_bytes']
    
    args_kind, args = ast_value[2]
    assert args_kind == LIST, "Function arguments must be a list"
    
    arg_offsets = {}
    for i, (arg_kind, arg) in enumerate(args):
        assert arg_kind == SYMBOL, "Function arguments must be symbols"
        assert arg not in arg_offsets, "Duplicate argument: {}".format(arg)

        # Args are above the saved return address, so the stack looks
        # like this.
        #
        # RBP + 24: arg_1
        # RBP + 16: arg_0
        # RBP + 8:  return address
        # RBP + 0:  saved RBP
        arg_offsets[arg] = 16 + i * 8

    context['arg_offsets'] = arg_offsets
    
    body = ast_value[3:]
    
    # The raw bytes of the instructions for the main function.
    fun_tmpl = []

    # Function prologue, setting up the stack.
    # push rbp
    fun_tmpl.extend([0x55])
    # mov rbp, rsp
    fun_tmpl.extend([0x48, 0x89, 0xE5])

    for subtree in body:
        fun_tmpl.extend(compile_expr(subtree, context))

    # Function epilogue.
    # mov rsp, rbp
    fun_tmpl.extend([0x48, 0x89, 0xEC])
    # pop rbp
    fun_tmpl.extend([0x5D])
    # ret
    fun_tmpl.extend([0xC3])

    context['instr_bytes'] += num_bytes(fun_tmpl)
    context.pop('locals')
    context.pop('arg_offsets')

    return fun_tmpl


def num_bytes_string_lit(value):
    # String literals are stored as:
    # * a 64-bit number representing the length
    # * the data itself
    # * a null byte for convenient linux interop
    return 8 + len(value) + 1


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
    context['data_offset'] += num_bytes_string_lit(value)

    return offset


def main(filename):
    with open(filename) as f:
        src = f.read()

    tokens = list(lex(src))
    defs = parse(tokens)

    defs_by_name = {}
    for def_ in defs:
        def_kind, def_value = def_
        assert def_kind == LIST, "Expected a list at the top level, got {}".format(def_kind)

        assert def_value and def_value[0] == (SYMBOL, 'defun'), "Expected a function definition, got: {!r}".format(def_value[0])
        assert len(def_value) > 3, "defun requires a name, parameters, and a body"

        name_kind, name_value = def_value[1]
        assert name_kind == SYMBOL, "defun requires a name"
        defs_by_name[name_value] = def_

    assert 'main' in defs_by_name, "A program must have a main function"

    context = {'string_literals': {}, 'data_offset': 0,
               'fun_offsets': {}, 'global_funs': defs_by_name,
               'instr_bytes': 0}

    instrs_tmpl = []
    instrs_tmpl.extend(compile_start(context))
    
    for ast in defs_by_name.values():
        instrs_tmpl.extend(compile_fun(ast, context))

    instrs = []
    for byte in instrs_tmpl:
        if isinstance(byte, int):
            instrs.append(byte)
        elif isinstance(byte, list) and len(byte) == 2 and byte[0] == 'string_lit':
            offset = byte[1]

            header_size = 120 # TODO: compute
            # String literals are immediately after code section.
            instrs.extend(int_64bit(ENTRY_POINT + header_size + num_bytes(instrs_tmpl) + offset))
        elif isinstance(byte, list) and len(byte) == 2 and byte[0] == 'fun_offset':
            fun_name = byte[1]
            absolute_offset = context['fun_offsets'][fun_name]
            # A relative is calculated relative to the current value
            # of rip, which is after the current CALL
            # instruction. We've only written the opcode so far, so
            # rip will be 4 additional bytes for the 32-bit immediate
            # offset.
            rip_value = len(instrs) + 4
            relative_offset = absolute_offset - rip_value
            instrs.extend(int_32bit(relative_offset))
        else:
            assert False, "Invalid template in instrs_tmpl: {!r}".format(byte)

    header = elf_header_instructions(instrs, context)

    # Given `foo.wlp`, write output binary `foo`.
    output_path = os.path.splitext(filename)[0]

    with open(output_path, 'wb') as f:
        f.write(bytes(header))
        f.write(bytes(instrs))
        # TODO: put string literals in a named section
        # Assumes dict is in insertion order (Python 3.6+)
        for string_literal in context['string_literals'].keys():
            # Strings are stored as a 64-bit integer of their length,
            # then their data.
            f.write(bytes(int_64bit(len(string_literal))))
            f.write(string_literal)
            f.write(b"\0")

    os.chmod(output_path, 0o744)


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: {} <path>".format(sys.argv[0]))
        sys.exit(1)
    
    main(sys.argv[1])
