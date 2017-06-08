
import io


class TextPecker:
    def __init__(self, s):
        self.str = s
        self.i = 0

    def read(self, n):
        self.i += n
        return self.str[self.i - n:self.i]

    def peek(self, n):
        if n >= 0:
            return self.str[self.i:self.i + n]
        else:
            return self.str[self.i + n - 1:self.i - 1]

    def peekline(self):
        out = ''
        i = self.i
        while i < len(self.str) and self.str[i] != '\n':
            out += self.str[i]
            i += 1
        return out

    def readline(self):
        out = self.peekline()
        self.i += len(out)
        return out


def rst_to_text(text, state_hook=None, references=None):
    """
    Convert rST to a more human text form.

    This is a very loose conversion. No advanced rST features are supported.
    The generated output directly depends on the input (e.g. indentation of
    admonitions).
    """
    state_hook = state_hook or (lambda old_state, new_state, out: None)
    references = references or {}
    state = 'text'
    text = TextPecker(text)
    out = io.StringIO()

    inline_single = ('*', '`')

    while True:
        char = text.read(1)
        if not char:
            break
        next = text.peek(1)  # type: str

        if state == 'text':
            if text.peek(-1) != '\\':
                if char in inline_single and next not in inline_single:
                    state_hook(state, char, out)
                    state = char
                    continue
                if char == next == '*':
                    state_hook(state, '**', out)
                    state = '**'
                    text.read(1)
                    continue
                if char == next == '`':
                    state_hook(state, '``', out)
                    state = '``'
                    text.read(1)
                    continue
                if text.peek(-1).isspace() and char == ':' and text.peek(5) == 'ref:`':
                    # translate reference
                    text.read(5)
                    ref = ''
                    while True:
                        char = text.peek(1)
                        if char == '`':
                            text.read(1)
                            break
                        if char == '\n':
                            text.read(1)
                            continue  # merge line breaks in :ref:`...\n...`
                        ref += text.read(1)
                    try:
                        out.write(references[ref])
                    except KeyError:
                        raise ValueError("Undefined reference in Archiver help: %r — please add reference substitution"
                                         "to 'rst_plain_text_references'" % ref)
                    continue
            if text.peek(-2) in ('\n\n', '') and char == next == '.':
                text.read(2)
                try:
                    directive, arguments = text.peekline().split('::', maxsplit=1)
                except ValueError:
                    directive = None
                text.readline()
                text.read(1)
                if not directive:
                    continue
                out.write(directive.title())
                out.write(':\n')
                if arguments:
                    out.write(arguments)
                    out.write('\n')
                continue
        if state in inline_single and char == state:
            state_hook(state, 'text', out)
            state = 'text'
            continue
        if state == '``' and char == next == '`':
            state_hook(state, 'text', out)
            state = 'text'
            text.read(1)
            continue
        if state == '**' and char == next == '*':
            state_hook(state, 'text', out)
            state = 'text'
            text.read(1)
            continue
        out.write(char)

    assert state == 'text', 'Invalid final state %r (This usually indicates unmatched */**)' % state
    return out.getvalue()


def ansi_escapes(old_state, new_state, out):
    if old_state == 'text' and new_state in ('*', '`', '``'):
        out.write('\033[4m')
    if old_state == 'text' and new_state == '**':
        out.write('\033[1m')
    if old_state in ('*', '`', '``', '**') and new_state == 'text':
        out.write('\033[0m')


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
