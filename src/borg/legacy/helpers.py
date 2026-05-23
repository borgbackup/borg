import stat


def borg1_hardlinkable(mode):
    return stat.S_ISREG(mode) or stat.S_ISBLK(mode) or stat.S_ISCHR(mode) or stat.S_ISFIFO(mode)


def borg1_hardlink_master(item):
    return item.get("hardlink_master", False) and "source" not in item and borg1_hardlinkable(item.mode)


def borg1_hardlink_slave(item):
    return "source" in item and borg1_hardlinkable(item.mode)
