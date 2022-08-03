# Support code for building docs (build_usage, build_man)

import os
import io
import re
import sys
import textwrap
from collections import OrderedDict
from datetime import datetime

from setuptools import Command


def long_desc_from_readme():
    with open("README.rst") as fd:
        long_description = fd.read()
        # remove header, but have one \n before first headline
        start = long_description.find("What is BorgBackup?")
        assert start >= 0
        long_description = "\n" + long_description[start:]
        # remove badges
        long_description = re.compile(r"^\.\. start-badges.*^\.\. end-badges", re.M | re.S).sub("", long_description)
        # remove unknown directives
        long_description = re.compile(r"^\.\. highlight:: \w+$", re.M).sub("", long_description)
        return long_description


def format_metavar(option):
    if option.nargs in ("*", "..."):
        return "[%s...]" % option.metavar
    elif option.nargs == "?":
        return "[%s]" % option.metavar
    elif option.nargs is None:
        return option.metavar
    else:
        raise ValueError(f"Can't format metavar {option.metavar}, unknown nargs {option.nargs}!")


class build_usage(Command):
    description = "generate usage for each command"

    user_options = [("output=", "O", "output directory")]

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        print("generating usage docs")
        import borg

        borg.doc_mode = "build_man"
        if not os.path.exists("docs/usage"):
            os.mkdir("docs/usage")
        # allows us to build docs without the C modules fully loaded during help generation
        from borg.archiver import Archiver

        parser = Archiver(prog="borg").build_parser()
        # borgfs has a separate man page to satisfy debian's "every program from a package
        # must have a man page" requirement, but it doesn't need a separate HTML docs page
        # borgfs_parser = Archiver(prog='borgfs').build_parser()

        self.generate_level("", parser, Archiver)

    def generate_level(self, prefix, parser, Archiver, extra_choices=None):
        is_subcommand = False
        choices = {}
        for action in parser._actions:
            if action.choices is not None and "SubParsersAction" in str(action.__class__):
                is_subcommand = True
                for cmd, parser in action.choices.items():
                    choices[prefix + cmd] = parser
        if extra_choices is not None:
            choices.update(extra_choices)
        if prefix and not choices:
            return
        print("found commands: %s" % list(choices.keys()))

        for command, parser in sorted(choices.items()):
            if command.startswith("debug"):
                print("skipping", command)
                continue
            print("generating help for %s" % command)

            if self.generate_level(command + " ", parser, Archiver):
                continue

            with open("docs/usage/%s.rst.inc" % command.replace(" ", "_"), "w") as doc:
                doc.write(".. IMPORTANT: this file is auto-generated from borg's built-in help, do not edit!\n\n")
                if command == "help":
                    for topic in Archiver.helptext:
                        params = {"topic": topic, "underline": "~" * len("borg help " + topic)}
                        doc.write(".. _borg_{topic}:\n\n".format(**params))
                        doc.write("borg help {topic}\n{underline}\n\n".format(**params))
                        doc.write(Archiver.helptext[topic])
                else:
                    params = {
                        "command": command,
                        "command_": command.replace(" ", "_"),
                        "underline": "-" * len("borg " + command),
                    }
                    doc.write(".. _borg_{command_}:\n\n".format(**params))
                    doc.write(
                        "borg {command}\n{underline}\n.. code-block:: none\n\n    borg [common options] {command}".format(
                            **params
                        )
                    )
                    self.write_usage(parser, doc)
                    epilog = parser.epilog
                    parser.epilog = None
                    self.write_options(parser, doc)
                    doc.write("\n\nDescription\n~~~~~~~~~~~\n")
                    doc.write(epilog)

        if "create" in choices:
            common_options = [group for group in choices["create"]._action_groups if group.title == "Common options"][0]
            with open("docs/usage/common-options.rst.inc", "w") as doc:
                self.write_options_group(common_options, doc, False, base_indent=0)

        return is_subcommand

    def write_usage(self, parser, fp):
        if any(len(o.option_strings) for o in parser._actions):
            fp.write(" [options]")
        for option in parser._actions:
            if option.option_strings:
                continue
            fp.write(" " + format_metavar(option))
        fp.write("\n\n")

    def write_options(self, parser, fp):
        def is_positional_group(group):
            return any(not o.option_strings for o in group._group_actions)

        # HTML output:
        # A table using some column-spans

        def html_write(s):
            for line in s.splitlines():
                fp.write("    " + line + "\n")

        rows = []
        for group in parser._action_groups:
            if group.title == "Common options":
                # (no of columns used, columns, ...)
                rows.append((1, ".. class:: borg-common-opt-ref\n\n:ref:`common_options`"))
            else:
                if not group._group_actions:
                    continue
                group_header = "**%s**" % group.title
                if group.description:
                    group_header += " — " + group.description
                rows.append((1, group_header))
                if is_positional_group(group):
                    for option in group._group_actions:
                        rows.append((3, "", "``%s``" % option.metavar, option.help or ""))
                else:
                    for option in group._group_actions:
                        if option.metavar:
                            option_fmt = "``%s " + option.metavar + "``"
                        else:
                            option_fmt = "``%s``"
                        option_str = ", ".join(option_fmt % s for s in option.option_strings)
                        option_desc = textwrap.dedent((option.help or "") % option.__dict__)
                        rows.append((3, "", option_str, option_desc))

        fp.write(".. only:: html\n\n")
        table = io.StringIO()
        table.write(".. class:: borg-options-table\n\n")
        self.rows_to_table(rows, table.write)
        fp.write(textwrap.indent(table.getvalue(), " " * 4))

        # LaTeX output:
        # Regular rST option lists (irregular column widths)
        latex_options = io.StringIO()
        for group in parser._action_groups:
            if group.title == "Common options":
                latex_options.write("\n\n:ref:`common_options`\n")
                latex_options.write("    |")
            else:
                self.write_options_group(group, latex_options)
        fp.write("\n.. only:: latex\n\n")
        fp.write(textwrap.indent(latex_options.getvalue(), " " * 4))

    def rows_to_table(self, rows, write):
        def write_row_separator():
            write("+")
            for column_width in column_widths:
                write("-" * (column_width + 1))
                write("+")
            write("\n")

        # Find column count and width
        column_count = max(columns for columns, *_ in rows)
        column_widths = [0] * column_count
        for columns, *cells in rows:
            for i in range(columns):
                # "+ 1" because we want a space between the cell contents and the delimiting "|" in the output
                column_widths[i] = max(column_widths[i], len(cells[i]) + 1)

        for columns, *original_cells in rows:
            write_row_separator()
            # If a cell contains newlines, then the row must be split up in individual rows
            # where each cell contains no newline.
            rowspanning_cells = []
            original_cells = list(original_cells)
            while any("\n" in cell for cell in original_cells):
                cell_bloc = []
                for i, cell in enumerate(original_cells):
                    pre, _, original_cells[i] = cell.partition("\n")
                    cell_bloc.append(pre)
                rowspanning_cells.append(cell_bloc)
            rowspanning_cells.append(original_cells)
            for cells in rowspanning_cells:
                for i, column_width in enumerate(column_widths):
                    if i < columns:
                        write("| ")
                        write(cells[i].ljust(column_width))
                    else:
                        write("  ")
                        write("".ljust(column_width))
                write("|\n")

        write_row_separator()
        # This bit of JavaScript kills the <colgroup> that is invariably inserted by docutils,
        # but does absolutely no good here. It sets bogus column widths which cannot be overridden
        # with CSS alone.
        # Since this is HTML-only output, it would be possible to just generate a <table> directly,
        # but then we'd lose rST formatting.
        write(
            textwrap.dedent(
                """
        .. raw:: html

            <script type='text/javascript'>
            $(document).ready(function () {
                $('.borg-options-table colgroup').remove();
            })
            </script>
        """
            )
        )

    def write_options_group(self, group, fp, with_title=True, base_indent=4):
        def is_positional_group(group):
            return any(not o.option_strings for o in group._group_actions)

        indent = " " * base_indent

        if is_positional_group(group):
            for option in group._group_actions:
                fp.write(option.metavar + "\n")
                fp.write(textwrap.indent(option.help or "", " " * base_indent) + "\n")
            return

        if not group._group_actions:
            return

        if with_title:
            fp.write("\n\n")
            fp.write(group.title + "\n")

        opts = OrderedDict()

        for option in group._group_actions:
            if option.metavar:
                option_fmt = "%s " + option.metavar
            else:
                option_fmt = "%s"
            option_str = ", ".join(option_fmt % s for s in option.option_strings)
            option_desc = textwrap.dedent((option.help or "") % option.__dict__)
            opts[option_str] = textwrap.indent(option_desc, " " * 4)

        padding = len(max(opts)) + 1

        for option, desc in opts.items():
            fp.write(indent + option.ljust(padding) + desc + "\n")


class build_man(Command):
    description = "build man pages"

    user_options = []

    see_also = {
        "create": ("delete", "prune", "check", "patterns", "placeholders", "compression"),
        "recreate": ("patterns", "placeholders", "compression"),
        "list": ("info", "diff", "prune", "patterns"),
        "info": ("list", "diff"),
        "rcreate": ("rdelete", "rlist", "check", "key-import", "key-export", "key-change-passphrase"),
        "key-import": ("key-export",),
        "key-export": ("key-import",),
        "mount": ("umount", "extract"),  # Would be cooler if these two were on the same page
        "umount": ("mount",),
        "extract": ("mount",),
        "delete": ("compact",),
        "prune": ("compact",),
    }

    rst_prelude = textwrap.dedent(
        """
    .. role:: ref(title)

    .. |project_name| replace:: Borg

    """
    )

    usage_group = {
        "break-lock": "lock",
        "with-lock": "lock",
        "key_change-passphrase": "key",
        "key_change-location": "key",
        "key_export": "key",
        "key_import": "key",
        "export-tar": "tar",
        "import-tar": "tar",
        "benchmark_crud": "benchmark",
        "benchmark_cpu": "benchmark",
        "umount": "mount",
    }

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        print("building man pages (in docs/man)", file=sys.stderr)
        import borg

        borg.doc_mode = "build_man"
        os.makedirs("docs/man", exist_ok=True)
        # allows us to build docs without the C modules fully loaded during help generation
        from borg.archiver import Archiver

        parser = Archiver(prog="borg").build_parser()
        borgfs_parser = Archiver(prog="borgfs").build_parser()

        self.generate_level("", parser, Archiver, {"borgfs": borgfs_parser})
        self.build_topic_pages(Archiver)
        self.build_intro_page()

    def generate_level(self, prefix, parser, Archiver, extra_choices=None):
        is_subcommand = False
        choices = {}
        for action in parser._actions:
            if action.choices is not None and "SubParsersAction" in str(action.__class__):
                is_subcommand = True
                for cmd, parser in action.choices.items():
                    choices[prefix + cmd] = parser
        if extra_choices is not None:
            choices.update(extra_choices)
        if prefix and not choices:
            return

        for command, parser in sorted(choices.items()):
            if command.startswith("debug") or command == "help":
                continue

            if command == "borgfs":
                man_title = command
            else:
                man_title = "borg-" + command.replace(" ", "-")
            print("building man page", man_title + "(1)", file=sys.stderr)

            is_intermediary = self.generate_level(command + " ", parser, Archiver)

            doc, write = self.new_doc()
            self.write_man_header(write, man_title, parser.description)

            self.write_heading(write, "SYNOPSIS")
            if is_intermediary:
                subparsers = [action for action in parser._actions if "SubParsersAction" in str(action.__class__)][0]
                for subcommand in subparsers.choices:
                    write("| borg", "[common options]", command, subcommand, "...")
                    self.see_also.setdefault(command, []).append(f"{command}-{subcommand}")
            else:
                if command == "borgfs":
                    write(command, end="")
                else:
                    write("borg", "[common options]", command, end="")
                self.write_usage(write, parser)
            write("\n")

            description, _, notes = parser.epilog.partition("\n.. man NOTES")

            if description:
                self.write_heading(write, "DESCRIPTION")
                write(description)

            if not is_intermediary:
                self.write_heading(write, "OPTIONS")
                write("See `borg-common(1)` for common options of Borg commands.")
                write()
                self.write_options(write, parser)

                self.write_examples(write, command)

            if notes:
                self.write_heading(write, "NOTES")
                write(notes)

            self.write_see_also(write, man_title)

            self.gen_man_page(man_title, doc.getvalue())

        # Generate the borg-common(1) man page with the common options.
        if "create" in choices:
            doc, write = self.new_doc()
            man_title = "borg-common"
            self.write_man_header(write, man_title, "Common options of Borg commands")

            common_options = [group for group in choices["create"]._action_groups if group.title == "Common options"][0]

            self.write_heading(write, "SYNOPSIS")
            self.write_options_group(write, common_options)
            self.write_see_also(write, man_title)
            self.gen_man_page(man_title, doc.getvalue())

        return is_subcommand

    def build_topic_pages(self, Archiver):
        for topic, text in Archiver.helptext.items():
            doc, write = self.new_doc()
            man_title = "borg-" + topic
            print("building man page", man_title + "(1)", file=sys.stderr)

            self.write_man_header(write, man_title, "Details regarding " + topic)
            self.write_heading(write, "DESCRIPTION")
            write(text)
            self.gen_man_page(man_title, doc.getvalue())

    def build_intro_page(self):
        doc, write = self.new_doc()
        man_title = "borg"
        print("building man page borg(1)", file=sys.stderr)

        with open("docs/man_intro.rst") as fd:
            man_intro = fd.read()

        self.write_man_header(write, man_title, "deduplicating and encrypting backup tool")
        self.gen_man_page(man_title, doc.getvalue() + man_intro)

    def new_doc(self):
        doc = io.StringIO(self.rst_prelude)
        doc.read()
        write = self.printer(doc)
        return doc, write

    def printer(self, fd):
        def write(*args, **kwargs):
            print(*args, file=fd, **kwargs)

        return write

    def write_heading(self, write, header, char="-", double_sided=False):
        write()
        if double_sided:
            write(char * len(header))
        write(header)
        write(char * len(header))
        write()

    def write_man_header(self, write, title, description):
        self.write_heading(write, title, "=", double_sided=True)
        self.write_heading(write, description, double_sided=True)
        # man page metadata
        write(":Author: The Borg Collective")
        write(":Date:", datetime.utcnow().date().isoformat())
        write(":Manual section: 1")
        write(":Manual group: borg backup tool")
        write()

    def write_examples(self, write, command):
        command = command.replace(" ", "_")
        with open("docs/usage/%s.rst" % self.usage_group.get(command, command)) as fd:
            usage = fd.read()
            usage_include = ".. include:: %s.rst.inc" % command
            begin = usage.find(usage_include)
            end = usage.find(".. include", begin + 1)
            # If a command has a dedicated anchor, it will occur before the command's include.
            if 0 < usage.find(".. _", begin + 1) < end:
                end = usage.find(".. _", begin + 1)
            examples = usage[begin:end]
            examples = examples.replace(usage_include, "")
            examples = examples.replace("Examples\n~~~~~~~~", "")
            examples = examples.replace("Miscellaneous Help\n------------------", "")
            examples = examples.replace("``docs/misc/prune-example.txt``:", "``docs/misc/prune-example.txt``.")
            examples = examples.replace(".. highlight:: none\n", "")  # we don't support highlight
            examples = re.sub("^(~+)$", lambda matches: "+" * len(matches.group(0)), examples, flags=re.MULTILINE)
            examples = examples.strip()
        if examples:
            self.write_heading(write, "EXAMPLES", "-")
            write(examples)

    def write_see_also(self, write, man_title):
        see_also = self.see_also.get(man_title.replace("borg-", ""), ())
        see_also = ["`borg-%s(1)`" % s for s in see_also]
        see_also.insert(0, "`borg-common(1)`")
        self.write_heading(write, "SEE ALSO")
        write(", ".join(see_also))

    def gen_man_page(self, name, rst):
        from docutils.writers import manpage
        from docutils.core import publish_string
        from docutils.nodes import inline
        from docutils.parsers.rst import roles

        def issue(name, rawtext, text, lineno, inliner, options={}, content=[]):
            return [inline(rawtext, "#" + text)], []

        roles.register_local_role("issue", issue)
        # We give the source_path so that docutils can find relative includes
        # as-if the document where located in the docs/ directory.
        man_page = publish_string(source=rst, source_path="docs/%s.rst" % name, writer=manpage.Writer())
        with open("docs/man/%s.1" % name, "wb") as fd:
            fd.write(man_page)

    def write_usage(self, write, parser):
        if any(len(o.option_strings) for o in parser._actions):
            write(" [options] ", end="")
        for option in parser._actions:
            if option.option_strings:
                continue
            write(format_metavar(option), end=" ")

    def write_options(self, write, parser):
        for group in parser._action_groups:
            if group.title == "Common options" or not group._group_actions:
                continue
            title = "arguments" if group.title == "positional arguments" else group.title
            self.write_heading(write, title, "+")
            self.write_options_group(write, group)

    def write_options_group(self, write, group):
        def is_positional_group(group):
            return any(not o.option_strings for o in group._group_actions)

        if is_positional_group(group):
            for option in group._group_actions:
                write(option.metavar)
                write(textwrap.indent(option.help or "", " " * 4))
            return

        opts = OrderedDict()

        for option in group._group_actions:
            if option.metavar:
                option_fmt = "%s " + option.metavar
            else:
                option_fmt = "%s"
            option_str = ", ".join(option_fmt % s for s in option.option_strings)
            option_desc = textwrap.dedent((option.help or "") % option.__dict__)
            opts[option_str] = textwrap.indent(option_desc, " " * 4)

        padding = len(max(opts)) + 1

        for option, desc in opts.items():
            write(option.ljust(padding), desc)
