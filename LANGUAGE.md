# Wilfred Lisp

A small, crude lisp.

## Syntax

### Comments

```
; This is a comment.
```

Comments start with `;` and last to the end of the line.

### Integers

```
1
123456789
```

Integers are 61-bit, and wrap around on overflow.

### Strings

```
"foo"
"bar\nbaz"
```

The only backslash sequences supported are `\n`, `\"` and `\\`.

### Booleans

```
true
false
```

<!-- end syntax -->

## Primitive expressions

Primitives are expressions that do not evaluate like functions.

They may not evaluate all their arguments (e.g. `if`), they may evaluate arguments
more than once (e.g. `while`), or they may not have a fixed number of
arguments (e.g. `do`).

### `defun` keyword

`defun` defines a global function.

```
(defun foo ()
  (print "hello\n")
  (print "world\n"))
```

### `if` primitive

```
(if true "true value" "ignored value") ; true value
```

Evaluates the second or the third argument depending on the boolean
value of the first argument.

### `let` primitive

```
(let (y "bye world\n"
      x "hello world\n")
  (print x)
  (print y))
```

Assigns local variables to the values specified, then evaluates the
last expression.

### `set!` primitive

```
(let (x 1)
  (set! x (+ x 1))
  (exit x))
```

Updates a local variable to a new value. The variable must be already
bound with `let`.

### `while` primitive

```
(while true
  (print "hello world\n"))
```

If the first argument evalutes to `true`, evaluate the second
argument, then repeat.

Currently returns `0` but this is an implementation detail that will
change.

### `do` primitive

```
(do
  (print "hello\n")
  1) ; 1
```

Evaluates its arguments in order, and returns the last value.

<!-- end primitives -->

## I/O functions

### `print` function

```
(print "hello world\n")
```

`print` writes its string argument to stdout.

### `exit` function

```
(exit 1)
```

`exit` terminates the program with the specified error code.

<!-- end I/O -->

## Integer functions

### `+` function

```
(+ 1 2) ; 3
```

`+` returns the sum of two integers.

### `-` function

```
(- 10 2) ; 8
```

`-` subtracts the second argument from the first argument. Both
arguments must be integers.

### `*` function

```
(* 2 3) ; 6
```

`*` returns the product of two integers.

### `<`, `<=`, `>`, `>=` functions

```
(< 1 2) ; true
(< 2 2) ; false
(< 3 2) ; false

(> 1 2)  ; false
(<= 1 2) ; true
(>= 1 2) ; true
```

Returns true if the first argument is less, greater or less/greater
and equal to the second. Requires integer arguments.

### `intdiv` function

```
(intdiv 6 2) ; 3
(intdiv 7 2) ; 3
(intdiv 8 2) ; 4
```

Divides the first argument by the second. Crashes the program if the
second argument is zero.

### `power` function

```
(power 10 3) ; 1000
```

Calculates the first argument to the power of the second argument.

### `shift-left`, `shift-right` functions

```
(shift-left 5 1)   ; 10
(shift-right 20 1) ; 10
```

Calculates the first argument bit-shifted left or right by the second
argument.

<!-- end integer functions -->

## Boolean functions

### `not` function

```
(not false) ; true
```

Negates a boolean value.

### `and` function

```
(and true false) ; false
```

Calculates boolean AND.

### `or` function

```
(or true false) ; true
```

Calculates boolean OR.

<!-- end boolean functions -->

## List functions

### `cons` function

```
(cons 2 nil)
```

Returns a new list with the first argument appended to the second
argument.

### `first` function

```
(first (cons 2 nil)) ; 2
```

Returns the first item of the cons cell given, or errors if not a cons
cell.

## String functions

### `string-length` function

```
(string-length "foo") ; 3
```

Returns the length of a string as an integer.

### `char-at` function

```
(char-at "abc" 0) ; 97
```

Returns the codepoint of the character in a string, at the position
specified.

<!-- end string functions -->

## `=` function

```
(= 1 1) ; true
(= 1 2) ; true

(= "a" "a") ; true
(= "a" "b") ; false

(= "a" 1) ; false
```

Compares its first argument wtih its second, and returns true if they
are equal. Integers are compared by value, strings by reference.

An integer and a string are never equal.

## File functions

### `file-exists?` function

```
(file-exists? "no-such-file.txt") ; false
```

Returns true if the file or directory specified exists.

### `slurp` function

```
(slurp "/etc/passwd") ; "root:x:0:0:..."
```

Returns contents of the file at the path specified.

### `delete!` function

```
(delete! "unwanted_file_path.txt")
```

Deletes the file at the path specified.


### `open` function

```
(open "/tmp/foo") ; 123
```

Opens the path specified for reading and writing. Returns the file
descriptor.

### `write!` function

```
; Writes 'a' to stdout.
(write 1 97)
```

Writes a single byte to the file descriptor specified.

### `chmod!` function

```
; Makes a.out executable with permissions 0o744.
(chmod! "a.out" 484)
```

Set permissions on the file at the path specified.

### `file-pos` function

```
(let (f (open "existing.txt"))
  (file-pos 0)) ;; 0
```

Returns the current offset in the file descriptor given.

### `file-seek!` function

```
(let (f (open "existing.txt"))
  (file-seek! f 5))
```

Sets the current offset in the file descriptor given.

### `file-seek-end!` function

```
(let (f (open "existing.txt"))
  (file-seek-end! f)) ;; Number of bytes in existing.txt
```

Seek to the end of file descriptor given, and return the offset.

<!-- end boolean functions -->

## `error` function

```
(error "something went wrong\n")
```

Writes the string to stderr, then terminates the program with exit
code 1.
