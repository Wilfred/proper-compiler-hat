# Wilfred Lisp

A small, crude lisp.

## Comments

```
; This is a comment.
```

Comments start with `;` and last to the end of the line.

## Integers

```
1
123456789
```

Integers are 62-bit, and wrap around on overflow.

## Strings

```
"foo"
"bar\nbaz"
```

The only backslash sequences supported are `\n`, `\"` and `\\`.

## Booleans

```
true
false
```

## `exit` function

```
(exit 1)
```

`exit` terminates the program with the specified error code.

## `print` function

```
(print "hello world\n")
```

`print` writes its string argument to stdout.

## `+` function

```
(+ 1 2) ; 3
```

`+` returns the sum of two integers.

## `-` function

```
(- 10 2) ; 8
```

`-` subtracts the second argument from the first argument. Both
arguments must be integers.

## `*` function

```
(* 2 3) ; 6
```

`*` returns the product of two integers.

## `not` function

```
(not false) ; true
```

Negates a boolean value.

## `if` primitive

```
(if true "true value" "ignored value") ; true value
```

Evaluates the second or the third argument depending on the boolean
value of the first argument.

## `string-length` function

```
(string-length "foo") ; 3
```

Returns the length of a string as an integer.

## `let` primitive

```
(let (y "bye world\n"
      x "hello world\n")
  (print x)
  (print y))
```

Assigns local variables to the values specified, then evaluates the
last expression.

## `set!` primitive

```
(let (x 1)
  (set! x (+ x 1))
  (exit x))
```

Updates a local variable to a new value. The variable must be already
bound with `let`.

## `while` primitive

```
(while true
  (print "hello world\n"))
```

If the first argument evalutes to `true`, evaluate the second
argument, then repeat.

Currently returns `0` but this is an implementation detail that will
change.

## `do` primitive

```
(do
  (print "hello\n")
  1) ; 1
```

Evaluates its arguments in order, and returns the last value.

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

## `<` function

```
(< 1 2) ; true
(< 2 2) ; false
(< 3 2) ; false
```

Returns true if the first argument is strictly less than the
second. Requires integer arguments.

## `>` function

```
(> 1 2) ; false
(> 2 2) ; false
(> 3 2) ; true
```

Returns true if the first argument is strictly greater than the
second. Requires integer arguments.

## `intdiv` function

```
(intdiv 6 2) ; 3
(intdiv 7 2) ; 3
(intdiv 8 2) ; 4
```

Divides the first argument by the second. Crashes the program if the
second argument is zero.

## `file-exists?` function

```
(file-exists? "no-such-file.txt") ; false
```

Returns true if the file or directory specified exists.

## `delete!` function

```
(delete! "unwanted_file_path.txt")
```

Deletes the file at the path specified.


## `open` function

```
(open "/tmp/foo") ; 123
```

Opens the path specified for writing. Returns the file descriptor.

## `write!` function

```
; Writes 'a' to stdout.
(write 1 97)
```

Writes a single byte to the file descriptor specified.

## `chmod!` function

```
; Makes a.out executable with permissions 0o744.
(chmod! "a.out" 484)
```

Set permissions on the file at the path specified.

## `error` function

```
(error "something went wrong\n")
```

Writes the string to stderr, then terminates the program with exit
code 1.

## `defun` keyword

`defun` defines a global function.

```
(defun foo ()
  (print "hello\n")
  (print "world\n"))
```
