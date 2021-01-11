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
(let (y "bye world"
      x "hello world")
  (print x))
```

Assigns local variables to the values specified, then evaluates the
last expression.
