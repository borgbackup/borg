import logging
import json
import os
import os.path
import sys
from borg.helpers.coverage_diy import register, mark

FALSISH = ("No", "NO", "no", "N", "n", "0")
TRUISH = ("Yes", "YES", "yes", "Y", "y", "1")
DEFAULTISH = ("Default", "DEFAULT", "default", "D", "d", "")

ERROR = "error"
assert ERROR not in TRUISH + FALSISH + DEFAULTISH


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
    """Output msg (usually a question) and let the user input an answer.
    Classify the answer according to falsish, truish, and defaultish as True, False, or the default.
    If it did not qualify and retry is False (no retries wanted), return the default (which
    defaults to False). If retry is True, let the user retry answering until the answer is qualified.

    If env_var_override is given and this variable is present in the environment, do not ask
    the user, but use the environment variable's contents as the answer as if it was typed in.
    Otherwise, read input from stdin and proceed as normal.
    If EOF is received instead of input, or an invalid input without a retry possibility,
    return the default.

    :param msg: introductory message to output on ofile; no \n is added [None]
    :param retry_msg: retry message to output on ofile; no \n is added [None]
    :param false_msg: message to output before returning False [None]
    :param true_msg: message to output before returning True [None]
    :param default_msg: message to output before returning the default [None]
    :param invalid_msg: message to output after an invalid answer is given [None]
    :param env_msg: message to output when using input from env_var_override ['{} (from {})'],
           must have two placeholders for the answer and the environment variable name
    :param falsish: sequence of answers qualifying as False
    :param truish: sequence of answers qualifying as True
    :param defaultish: sequence of answers qualifying as the default
    :param default: default return value (defaultish answer was given or no-answer condition) [False]
    :param retry: if True and input is incorrect, retry; otherwise return the default [True]
    :param env_var_override: environment variable name [None]
    :param ofile: output stream [sys.stderr]
    :param input: input function [input from builtins]
    :return: boolean answer value, True or False
    """
    
    # Setup for DIY coverage
    YES_BRANCHES = [
        "YES_01_invalid_default",
        "YES_02_ofile_none",
                "YES_03_answer_is_error",
        "YES_04_msg_printed",
        "YES_05_env_override_set",
        "YES_06_env_override_none",
        "YES_07_env_answer_used",
        "YES_08_env_answer_none",
        "YES_09_prompt_false_return_default",
        "YES_10_input_success",
        "YES_11_input_error_eof",
        "YES_12_input_error_unicode",
        "YES_13_answer_in_defaultish",
        "YES_14_default_msg_printed",
        "YES_15_answer_in_truish",
        "YES_16_true_msg_printed",
        "YES_17_answer_in_falsish",
        "YES_18_false_msg_printed",
        "YES_19_invalid_answer_retry",
        "YES_20_invalid_answer_no_retry",
        "YES_21_retry_msg_printed",
    ]
    for bid in YES_BRANCHES:
        register(bid)

    def output(msg, msg_type, is_prompt=False, **kwargs):
        json_output = getattr(logging.getLogger("borg"), "json", False)
        if json_output:
            kwargs |= dict(type="question_%s" % msg_type, msgid=msgid, message=msg)
            print(json.dumps(kwargs), file=sys.stderr)
        else:
            if is_prompt:
                print(msg, file=ofile, end="", flush=True)
            else:
                print(msg, file=ofile)

    msgid = msgid or env_var_override
    # note: we do not assign sys.stderr as the default above, so it is
    # really evaluated NOW, not at function definition time.
    if ofile is None:
        mark("YES_02_ofile_none")
        ofile = sys.stderr
    if default not in (True, False):
        mark("YES_01_invalid_default")
        raise ValueError("invalid default value, must be True or False")
    if msg:
        mark("YES_04_msg_printed")
        output(msg, "prompt", is_prompt=True)
    while True:
        answer = None
        if env_var_override:
            mark("YES_05_env_override_set")
            answer = os.environ.get(env_var_override)
            if answer is not None and env_msg:
                mark("YES_07_env_answer_used")
                output(env_msg.format(answer, env_var_override), "env_answer", env_var=env_var_override)
            else:
                mark("YES_08_env_answer_none")
        else:
            mark("YES_06_env_override_none")
        
        if answer is None:
            if not prompt:
                mark("YES_09_prompt_false_return_default")
                return default
            try:
                answer = input()  # this may raise UnicodeDecodeError, #6984
                mark("YES_10_input_success")
                if answer == ERROR:  # for testing purposes
                    mark("YES_03_answer_is_error")
                    raise UnicodeDecodeError("?", b"?", 0, 1, "?")  # args don't matter
            except EOFError:
                # avoid defaultish[0], defaultish could be empty
                mark("YES_11_input_error_eof")
                answer = truish[0] if default else falsish[0]
            except UnicodeDecodeError:
                mark("YES_12_input_error_unicode")
                answer = ERROR
                
        if answer in defaultish:
            mark("YES_13_answer_in_defaultish")
            if default_msg:
                mark("YES_14_default_msg_printed")
                output(default_msg, "accepted_default")
            return default
        if answer in truish:
            mark("YES_15_answer_in_truish")
            if true_msg:
                mark("YES_16_true_msg_printed")
                output(true_msg, "accepted_true")
            return True
        if answer in falsish:
            mark("YES_17_answer_in_falsish")
            if false_msg:
                mark("YES_18_false_msg_printed")
                output(false_msg, "accepted_false")
            return False
        # if we get here, the answer was invalid
        if invalid_msg:
            mark("YES_19_invalid_answer_retry")
            output(invalid_msg, "invalid_answer")
        if not retry:
            mark("YES_20_invalid_answer_no_retry")
            return default
        if retry_msg:
            mark("YES_21_retry_msg_printed")
            output(retry_msg, "prompt_retry", is_prompt=True)
        # in case we used an environment variable and it gave an invalid answer, do not use it again:
        env_var_override = None
