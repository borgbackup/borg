import logging
import json
import os
import os.path
import sys

FALSISH = ("No", "NO", "no", "N", "n", "0")
TRUISH = ("Yes", "YES", "yes", "Y", "y", "1")
DEFAULTISH = ("Default", "DEFAULT", "default", "D", "d", "")


def yes(
    msg=None,
    false_msg=None,
    true_msg=None,
    default_msg=None,
    retry_msg=None,
    invalid_msg=None,
    env_msg="{} (from {})",
    falsish=FALSISH,
    truish=TRUISH,
    defaultish=DEFAULTISH,
    default=False,
    retry=True,
    env_var_override=None,
    ofile=None,
    input=input,
    prompt=True,
    msgid=None,
):
    """Output <msg> (usually a question) and let user input an answer.
    Qualifies the answer according to falsish, truish and defaultish as True, False or <default>.
    If it didn't qualify and retry is False (no retries wanted), return the default [which
    defaults to False]. If retry is True let user retry answering until answer is qualified.

    If env_var_override is given and this var is present in the environment, do not ask
    the user, but just use the env var contents as answer as if it was typed in.
    Otherwise read input from stdin and proceed as normal.
    If EOF is received instead an input or an invalid input without retry possibility,
    return default.

    :param msg: introducing message to output on ofile, no \n is added [None]
    :param retry_msg: retry message to output on ofile, no \n is added [None]
    :param false_msg: message to output before returning False [None]
    :param true_msg: message to output before returning True [None]
    :param default_msg: message to output before returning a <default> [None]
    :param invalid_msg: message to output after a invalid answer was given [None]
    :param env_msg: message to output when using input from env_var_override ['{} (from {})'],
           needs to have 2 placeholders for answer and env var name
    :param falsish: sequence of answers qualifying as False
    :param truish: sequence of answers qualifying as True
    :param defaultish: sequence of answers qualifying as <default>
    :param default: default return value (defaultish answer was given or no-answer condition) [False]
    :param retry: if True and input is incorrect, retry. Otherwise return default. [True]
    :param env_var_override: environment variable name [None]
    :param ofile: output stream [sys.stderr]
    :param input: input function [input from builtins]
    :return: boolean answer value, True or False
    """

    def output(msg, msg_type, is_prompt=False, **kwargs):
        json_output = getattr(logging.getLogger("borg"), "json", False)
        if json_output:
            kwargs.update(dict(type="question_%s" % msg_type, msgid=msgid, message=msg))
            print(json.dumps(kwargs), file=sys.stderr)
        else:
            if is_prompt:
                print(msg, file=ofile, end="", flush=True)
            else:
                print(msg, file=ofile)

    msgid = msgid or env_var_override
    # note: we do not assign sys.stderr as default above, so it is
    # really evaluated NOW,  not at function definition time.
    if ofile is None:
        ofile = sys.stderr
    if default not in (True, False):
        raise ValueError("invalid default value, must be True or False")
    if msg:
        output(msg, "prompt", is_prompt=True)
    while True:
        answer = None
        if env_var_override:
            answer = os.environ.get(env_var_override)
            if answer is not None and env_msg:
                output(env_msg.format(answer, env_var_override), "env_answer", env_var=env_var_override)
        if answer is None:
            if not prompt:
                return default
            try:
                answer = input()
            except EOFError:
                # avoid defaultish[0], defaultish could be empty
                answer = truish[0] if default else falsish[0]
        if answer in defaultish:
            if default_msg:
                output(default_msg, "accepted_default")
            return default
        if answer in truish:
            if true_msg:
                output(true_msg, "accepted_true")
            return True
        if answer in falsish:
            if false_msg:
                output(false_msg, "accepted_false")
            return False
        # if we get here, the answer was invalid
        if invalid_msg:
            output(invalid_msg, "invalid_answer")
        if not retry:
            return default
        if retry_msg:
            output(retry_msg, "prompt_retry", is_prompt=True)
        # in case we used an environment variable and it gave an invalid answer, do not use it again:
        env_var_override = None
