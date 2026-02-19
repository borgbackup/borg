import io
import sys

from . import is_terminal

coverage_hits = {i: False for i in range(1, 26)}

class TextPecker:
    def __init__(self, s):
        self.str = s
        self.i = 0

    def read(self, n):
        self.i += n
        return self.str[self.i - n : self.i]

    def peek(self, n):
        if n >= 0:
            return self.str[self.i : self.i + n]
        else:
            return self.str[self.i + n - 1 : self.i - 1]

    def peekline(self):
        out = ""
        i = self.i
        while i < len(self.str) and self.str[i] != "\n":
            out += self.str[i]
            i += 1
        return out

    def readline(self):
        out = self.peekline()
        self.i += len(out)
        return out


def process_directive(directive, arguments, out, state_hook):
    if directive == "container" and arguments == "experimental":
        state_hook("text", "**", out)
        out.write("++ Experimental ++")
        state_hook("**", "text", out)
    else:
        state_hook("text", "**", out)
        out.write(directive.title())
        out.write(":\n")
        state_hook("**", "text", out)
        if arguments:
            out.write(arguments)
            out.write("\n")


def rst_to_text(text, state_hook=None, references=None):
    """
    Convert rST to a more human-friendly text form.

    This is a very loose conversion. No advanced rST features are supported.
    The generated output depends directly on the input (for example, the
    indentation of admonitions).
    """
    state_hook = state_hook or (lambda old_state, new_state, out: None)
    references = references or {}
    state = "text"
    inline_mode = "replace"
    text = TextPecker(text)
    out = io.StringIO()

    inline_single = ("*", "`")

    while True:
        coverage_hits[1] = True
        char = text.read(1)
        if not char:
            coverage_hits[2] = True
            break
        else:
            coverage_hits[3] = True
        next = text.peek(1)  # type: str

        if state == "text":
            coverage_hits[4] = True
            if char == "\\" and text.peek(1) in inline_single:
                coverage_hits[6] = True
                continue
            else:
                coverage_hits[7] = True
            if text.peek(-1) != "\\":
                coverage_hits[8] = True
                if char in inline_single and next != char:
                    coverage_hits[10] = True
                    state_hook(state, char, out)
                    state = char
                    continue
                if char == next == "*":
                    coverage_hits[11] = True
                    state_hook(state, "**", out)
                    state = "**"
                    text.read(1)
                    continue
                if char == next == "`":
                    coverage_hits[12] = True
                    state_hook(state, "``", out)
                    state = "``"
                    text.read(1)
                    continue
                if text.peek(-1).isspace() and char == ":" and text.peek(5) == "ref:`":
                    coverage_hits[13] = True
                    # translate reference
                    text.read(5)
                    ref = ""
                    while True:
                        coverage_hits[14] = True
                        char = text.peek(1)
                        if char == "`":
                            coverage_hits[15] = True
                            text.read(1)
                            break
                        if char == "\n":
                            coverage_hits[16] = True
                            text.read(1)
                            continue  # merge line breaks in :ref:`...\n...`
                        ref += text.read(1)
                    try:
                        coverage_hits[17] = True
                        out.write(references[ref])
                    except KeyError:
                        coverage_hits[18] = True
                        raise ValueError(
                            "Undefined reference in Archiver help: %r — please add reference "
                            "substitution to 'rst_plain_text_references'" % ref
                        )
                    continue
                if char == ":" and text.peek(2) == ":\n":  # End of line code block
                    coverage_hits[19] = True
                    text.read(2)
                    state_hook(state, "code-block", out)
                    state = "code-block"
                    out.write(":\n")
                    continue
            else:
                coverage_hits[9] = True

            if text.peek(-2) in ("\n\n", "") and char == next == ".":
                coverage_hits[20] = True
                text.read(2)
                directive, is_directive, arguments = text.readline().partition("::")
                text.read(1)
                if not is_directive:
                    coverage_hits[21] = True
                    # partition: if the separator is not in the text, the leftmost output is the entire input
                    if directive == "nanorst: inline-fill":
                        inline_mode = "fill"
                    elif directive == "nanorst: inline-replace":
                        inline_mode = "replace"
                    continue
                process_directive(directive, arguments.strip(), out, state_hook)
                continue
        else:
            coverage_hits[5] = True
        if state in inline_single and char == state:
            coverage_hits[22] = True
            state_hook(state, "text", out)
            state = "text"
            if inline_mode == "fill":
                out.write(2 * " ")
            continue
        if state == "``" and char == next == "`":
            coverage_hits[23] = True
            state_hook(state, "text", out)
            state = "text"
            text.read(1)
            if inline_mode == "fill":
                out.write(4 * " ")
            continue
        if state == "**" and char == next == "*":
            coverage_hits[24] = True
            state_hook(state, "text", out)
            state = "text"
            text.read(1)
            continue
        if state == "code-block" and char == next == "\n" and text.peek(5)[1:] != "    ":
            coverage_hits[25] = True
            # Foo::
            #
            #     *stuff* *code* *ignore .. all markup*
            #
            #     More arcane stuff
            #
            # Regular text...
            state_hook(state, "text", out)
            state = "text"
        out.write(char)

    assert state == "text", "Invalid final state %r (This usually indicates unmatched */**)" % state
    return out.getvalue()


class RstToTextLazy:
    def __init__(self, str, state_hook=None, references=None):
        self.str = str
        self.state_hook = state_hook
        self.references = references
        self._rst = None

    @property
    def rst(self):
        if self._rst is None:
            self._rst = rst_to_text(self.str, self.state_hook, self.references)
        return self._rst

    def __getattr__(self, item):
        return getattr(self.rst, item)

    def __str__(self):
        return self.rst

    def __add__(self, other):
        return self.rst + other

    def __iter__(self):
        return iter(self.rst)

    def __contains__(self, item):
        return item in self.rst


def ansi_escapes(old_state, new_state, out):
    if old_state == "text" and new_state in ("*", "`", "``"):
        out.write("\033[4m")
    if old_state == "text" and new_state == "**":
        out.write("\033[1m")
    if old_state in ("*", "`", "``", "**") and new_state == "text":
        out.write("\033[0m")


def rst_to_terminal(rst, references=None, destination=sys.stdout):
    """
    Convert *rst* to a lazy string.

    If *destination* is a file-like object connected to a terminal,
    enrich the text with suitable ANSI escapes. Otherwise, return plain text.
    """
    if is_terminal(destination):
        rst_state_hook = ansi_escapes
    else:
        rst_state_hook = None
    return RstToTextLazy(rst, rst_state_hook, references)
