import stat


def borg1_hardlinkable(mode):
    return stat.S_ISREG(mode) or stat.S_ISBLK(mode) or stat.S_ISCHR(mode) or stat.S_ISFIFO(mode)


def borg1_hardlink_with_content(item):
    """Is this a borg1 hard link item that carries the content of its hard link group?

    borg1 stored a group of hard links asymmetrically: the first item encountered got the
    chunks list, every later one only got a .source back reference to that item's path.
    Note that the 'hardlink_master' key does not tell these apart: since #7175 it is set
    for all hardlinkable items, so the absence of .source is what identifies the item
    that has the content.
    """
    return item.get("hardlink_master", False) and "source" not in item and borg1_hardlinkable(item.mode)


def borg1_hardlink_reference(item):
    """Is this a borg1 hard link item that only back references the item with the content?"""
    return "source" in item and borg1_hardlinkable(item.mode)
