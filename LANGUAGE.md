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

The only backslash code supported is `\n`.

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
(+ 1 2)
```

`+` returns the sum of two integers.

## `bool-to-string` function

```
(bool-to-string true) ; "true"
```

Converts a boolean value to a string representation.

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
