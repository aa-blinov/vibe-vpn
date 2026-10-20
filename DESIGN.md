---
name: vibe-vpn
description: A terminal program with no visual identity of its own; the output is plain text and nothing else.
colors:
  none: "the program writes no escape sequences, so the output takes the colour of the terminal"
typography:
  body:
    fontFamily: "terminal default, monospace"
    fontSize: "terminal default"
    fontWeight: 400
    lineHeight: 1.2
  title:
    fontFamily: "terminal default, monospace"
    fontSize: "terminal default"
    fontWeight: 700
    lineHeight: 1.2
rounded:
  none: "0px"
spacing:
  indent: "2 spaces"
  column: "2 columns"
---

# Design system: vibe-vpn

## Overview

**Creative North Star: "a line of plain text on a terminal"**

This project has no visual identity. There is no window, no page, no
stylesheet, no icon and no image. `vibe-vpn` is a command line program, and
everything a person sees is a line of text in a terminal.

The repository emits no ANSI escape sequence anywhere. There is no colour
code, no bold, no cursor movement and no box drawing. The output takes the
palette of whatever terminal it runs in, and the only thing the project
controls is the words and the layout of those lines.

That is a deliberate choice for a project whose subject is traffic shaping.
A program that disguises its traffic does not need a disguise of its own,
and a colour code in a log line is one more byte in a captured session.
The consequence is that the interface cannot be differentiated, and every
line has to carry its meaning in the words themselves.

What the repository does own is a small set of text conventions, and they
are consistent across the Go binary, the shell script and the installer.

Key characteristics:

- no colour, no styling, no escape sequence;
- one line per fact, and the fact is a number;
- errors are one line, prefixed, on standard error;
- the usage text is a fixed block with a fixed indent.

## Colors

There are none, and that is the record.

The Go program writes plain text through `fmt` and the standard `log`
package, and neither of them adds styling. A search for an escape
sequence across `cmd/` and `internal/` finds nothing. The shell script and
the installer use `printf` and `echo` for the same reason.

The colours that a reader sees are the terminal's, and the project has no
say in them. There is no light and no dark set, no accent, and no token
that a theme could change.

### Named rules

**The Plain Text Rule.** No line of output carries an escape sequence. The
terminal decides the colour, and the words carry the meaning.

**The Terminal Inherits Rule.** Nothing in the output depends on a colour,
a bold face or a background. Every line has to be readable in a pipe, in a
log file and in a terminal with a monochrome scheme.

## Typography

**Display Font:** the terminal's.
**Body Font:** the terminal's.

There is no font file and no font stack. The text is rendered by the
terminal, in whatever family and at whatever size the terminal uses.

The project controls the shape of each line:

- **Key and value.** The statistics line is a run of `key=value` pairs,
  separated by a single space, with no punctuation between them.
- **Prefix.** An error is `error: ` followed by the message. Nothing else in
  the program carries a prefix.
- **Indent.** The usage block indents its verbs by two spaces and its
  flags by two more.
- **Case.** Lower case for the words of a message, lower case for the keys
  of the statistics line, and the one exception is the unit suffix of a
  duration, which is the one the `time` package prints.

### Named rules

**The One Line Rule.** One fact per line, and the line is a complete
sentence of a machine-readable kind. The statistics line is the strict case:
every pair is `key=value`, and a person reads it as a table.

## Layout

The program's output has three shapes, and the shape is decided by what
produced it.

**The usage block.** One header line, then the verb list, then the flag
list. The verbs are indented by two spaces, and the description of a verb
that needs a second line is indented by 44 spaces so that it lines up under
the first.

**The statistics line.** A single line of `key=value` pairs, written to the
log every `stats_interval` seconds. The order of the pairs is fixed, so two
lines can be compared with `diff`.

**The setup output.** `vibe-vpn setup server` prints where it wrote and the
command that starts it, and the command is the one that was printed above
it.

The shell script and the installer have their own markers. The script
prints a step as `[==>] <what it is doing>`, and the installer prints one as
`==> <what it is doing>`. Neither marker is coloured and neither is
indented.

There is no width to design for. A line that is too long wraps in the
terminal, and the project does not try to prevent it.

## Elevation & Depth

There is none. A terminal has no layers, and the program adds none: there
is no box, no rule, no shadow and no background. The only thing that
separates one message from the next is the newline.

## Shapes

There are none. Nothing is drawn, so there is no radius and no border.

## Components

### The usage block

- **Shape:** a fixed block of plain text on standard error.
- **Header:** `vibe-vpn - research VPN prototype`, one line.
- **Verbs:** two spaces of indent, the verb, then the arguments.
- **Flags:** two spaces of indent, the flag, then the description.

### The statistics line

- **Shape:** one line, `key=value` pairs separated by a single space.
- **Order:** fixed. `role`, the four counters, `dropped`, `handshakes`,
  `handshake`, `reconnects`, `rekeys`, `rtt`, `loss`, then the five size
  buckets.
- **Units:** the counters are bare numbers, the duration is what the `time`
  package prints, and the size buckets are a slash-separated group.

### The error line

- **Shape:** `error: <message>`, one line, on standard error.
- **Rule:** the message names what failed and, where the program knows it,
  the number. The exit code is 1.

### The shell prompts

- **Shape:** `read -rp`, so the prompt and the answer share a line.
- **Default:** the default value in square brackets before the colon, and
  an empty answer takes it.
- **Steps:** `[==>] <step>` in the script, `==> <step>` in the installer.

### The metrics endpoint

- **Shape:** the Prometheus text format, served on a loopback address.
- **Rule:** the address is configured, and it is never a public one.

## Do's and Don'ts

### Don't:

- **Don't** add an escape sequence to any output line. The traffic this
  program carries is meant to look like nothing, and its own output is
  meant to look like nothing too.
- **Don't** add a colour, a bold face or a background to a message. The
  meaning has to be in the words, because the output ends up in a log file.
- **Don't** draw a box, a rule or a separator between messages.
- **Don't** change the order of the pairs in the statistics line. Two
  statistics lines are compared with `diff`, and the order is what makes
  that work.
- **Don't** let a message run to more than one line, except in the usage
  block, where the continuation lines are indented to line up.

### Do:

- **Do** put the number in the message. The port, the address, the packet
  count and the duration belong in the line that says what happened.
- **Do** write errors on standard error with the `error: ` prefix, and
  leave standard output for the result.
- **Do** keep the two-space indent in the usage block and the flag list.
- **Do** keep the markers of the script and of the installer as they are,
  so that a transcript of either reads the same way.
