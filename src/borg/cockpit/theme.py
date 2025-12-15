"""
Borg Theme Definition.
"""

from textual.theme import Theme

theme = Theme(
    name="borg",
    primary="#00FF00",
    secondary="#000000",  # text on top of $primary background
    error="#FF0000",
    warning="#FFA500",
    success="#00FF00",
    accent="#00FF00",  # highlighted interactive elements
    foreground="#00FF00",  # default text color
    background="#000000",
    surface="#000000",  # bg col of lowest layer
    panel="#444444",  # bg col of panels, containers, cards, sidebars, modal dialogs, etc.
    dark=True,
    variables={
        "block-cursor-text-style": "none",
        "input-selection-background": "#00FF00 35%",
        "pulsar-color": "#ffffff",
        "pulsar-dim-color": "#000000",
        "star-color": "#888888",
        "star-bright-color": "#ffffff",
        "logo-color": "#00dd00",
    },
)
