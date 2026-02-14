from .errors import RTError


def check_extension_modules():
    from .. import platform, compress, crypto, item, hashindex, chunkers

    msg = """The Borg binary extension modules do not seem to be properly installed."""
    if hashindex.API_VERSION != "1.2_01":
        raise RTError(msg)
    if chunkers.API_VERSION != "1.2_01":
        raise RTError(msg)
    if compress.API_VERSION != "1.2_02":
        raise RTError(msg)
    if crypto.low_level.API_VERSION != "1.3_01":
        raise RTError(msg)
    if item.API_VERSION != "1.2_01":
        raise RTError(msg)
    if platform.API_VERSION != platform.OS_API_VERSION or platform.API_VERSION != "1.2_05":
        raise RTError(msg)
