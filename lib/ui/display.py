# Copyright (c) 2026 waymap developers
# See the file 'LICENSE' for copying permission.

"""UI components and display utilities."""

import os
import time
import sys
from typing import List, Tuple, Optional


def _configure_utf8_output() -> None:
    """Use UTF-8 on stdout/stderr when the terminal supports reconfiguration."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (OSError, ValueError, AttributeError):
                pass


def _safe_print(text: str = "", **kwargs) -> None:
    """Print text, falling back when the console cannot encode Unicode."""
    try:
        print(text, **kwargs)
    except UnicodeEncodeError:
        encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
        safe_text = text.encode(encoding, errors="replace").decode(encoding, errors="replace")
        print(safe_text, **kwargs)


_configure_utf8_output()


class Colors:
    """ANSI color codes."""
    GREY = "\033[90m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    RESET = "\033[0m"
    BOLD = "\033[1m"


def colored(text: str, color: str) -> str:
    """
    Apply color to text.
    
    Args:
        text: Text to color
        color: Color name
        
    Returns:
        Colored text string
    """
    color_map = {
        "grey": Colors.GREY,
        "red": Colors.RED,
        "green": Colors.GREEN,
        "yellow": Colors.YELLOW,
        "blue": Colors.BLUE,
        "magenta": Colors.MAGENTA,
        "cyan": Colors.CYAN,
        "white": Colors.WHITE,
        "bold": Colors.BOLD,
    }
    color_code = color_map.get(color, "")
    return f"{color_code}{text}{Colors.RESET}" if color_code else text


def print_separator(char: str = "─", color: str = "cyan", length: int = 60) -> None:
    """Print a decorative separator line."""
    _safe_print(colored(char * length, color))


def print_header(text: str, color: str = "yellow", top_padding: int = 1, bottom_padding: int = 1) -> None:
    """Print a formatted header."""
    if top_padding:
        _safe_print()
    border = "═" * (len(text) + 2)
    _safe_print(colored(f"╔{border}╗", color))
    _safe_print(colored(f"║ {text.upper()} ║", color))
    _safe_print(colored(f"╚{border}╝", color))
    if bottom_padding:
        _safe_print()


def print_status(message: str, status_type: str = "info", icon: Optional[str] = None) -> None:
    """
    Print status messages with colored icons.
    
    Args:
        message: Message to display
        status_type: Type of status (info, success, warning, error, debug)
        icon: Optional custom icon
    """
    if status_type == "debug" and os.environ.get("WAYMAP_VERBOSE") != "1":
        return

    colors = {
        "info": "cyan",
        "success": "green",
        "warning": "yellow",
        "error": "red",
        "debug": "blue"
    }
    icons = {
        "info": "•",
        "success": "✓",
        "warning": "⚠",
        "error": "✗",
        "debug": "⚙"
    }
    color = colors.get(status_type, "white")
    icon_char = icon if icon else icons.get(status_type, "•")
    _safe_print(colored(f"[{icon_char}] {message}", color))


def print_success(message: str) -> None:
    """Print a success status message."""
    print_status(message, "success")


def print_warning(message: str) -> None:
    """Print a warning status message."""
    print_status(message, "warning")


def print_error(message: str) -> None:
    """Print an error status message."""
    print_status(message, "error")


def print_progress_bar(
    iteration: int,
    total: int,
    prefix: str = 'Progress:',
    suffix: str = 'Complete',
    length: int = 40,
    fill: str = '█'
) -> None:
    """Display a progress bar."""
    if total == 0:
        return
    
    percent = f"{100 * (iteration / float(total)):.1f}"
    filled_length = int(length * iteration // total)
    bar = fill * filled_length + '░' * (length - filled_length)
    print(f'\r{prefix} |{bar}| {percent}% {suffix}', end='\r')
    if iteration == total:
        print()


def animate_loading(
    text: str,
    duration: float = 2.0,
    frames: List[str] = None
) -> None:
    """Animated loading indicator."""
    if frames is None:
        frames = ["⣾", "⣽", "⣻", "⢿", "⡿", "⣟", "⣯", "⣷"]
    
    end_time = time.time() + duration
    frame_index = 0
    while time.time() < end_time:
        print(f"\r{colored(frames[frame_index], 'cyan')} {text}", end="")
        sys.stdout.flush()
        frame_index = (frame_index + 1) % len(frames)
        time.sleep(0.1)
    print("\r" + " " * (len(text) + 2) + "\r", end="")
    sys.stdout.flush()


def print_table(
    headers: List[str],
    data: List[List[str]],
    col_colors: Optional[List[str]] = None
) -> None:
    """
    Print data in a formatted table.
    
    Args:
        headers: Column headers
        data: Data rows
        col_colors: Optional colors for each column
    """
    if not data:
        return
    
    # Calculate column widths
    col_widths = [len(str(header)) for header in headers]
    for row in data:
        for i, item in enumerate(row):
            if i < len(col_widths):
                col_widths[i] = max(col_widths[i], len(str(item)))
    
    total_width = sum(col_widths) + len(headers) * 3 - 1
    
    # Print header
    print(colored("╔" + "═" * total_width + "╗", "cyan"))
    header_line = "║"
    for i, header in enumerate(headers):
        if i < len(col_widths):
            header_line += f" {colored(str(header).ljust(col_widths[i]), 'yellow')} ║"
    print(header_line)
    print(colored("╠" + "═" * total_width + "╣", "cyan"))
    
    # Print data
    for row in data:
        row_line = "║"
        for i, item in enumerate(row):
            if i < len(col_widths):
                color = col_colors[i] if col_colors and i < len(col_colors) else "white"
                row_line += f" {colored(str(item).ljust(col_widths[i]), color)} ║"
        print(row_line)
    
    print(colored("╚" + "═" * total_width + "╝", "cyan"))


def print_banner() -> None:
    """Print the waymap banner."""
    from lib.core.config import get_config
    cfg = get_config()

    banner = rf"""

┓ ┏┏┓┓┏┳┳┓┏┓┏┓
┃┃┃┣┫┗┫┃┃┃┣┫┃┃
┗┻┛┛┗┗┛┛ ┗┛┗┣┛
  Web Vulnerability Scanner  v{cfg.VERSION}
    """
    ascii_banner = rf"""

 __        __  ___  __  __
 \ \      / / / _ \|  \/  |
  \ \ /\ / / | | | | |\/| |
   \ V  V /  | |_| | |  | |
    \_/\_/    \___/|_|  |_|

  Web Vulnerability Scanner  v{cfg.VERSION}
    """
    try:
        _safe_print(colored(banner, 'cyan'))
    except UnicodeEncodeError:
        _safe_print(colored(ascii_banner, 'cyan'))
    print_separator("═", "cyan", 70)
    _safe_print(colored(f"Version: {cfg.VERSION:>50}", 'yellow'))
    _safe_print(colored(f"Author:  {cfg.AUTHOR:>50}", 'yellow'))
    _safe_print(colored(f"{cfg.COPYRIGHT:>70}", 'yellow'))
    print_separator("═", "cyan", 70)
    _safe_print()


def clear_line() -> None:
    """Clear the current line."""
    print("\r" + " " * 80 + "\r", end="")
    sys.stdout.flush()


def prompt_line(prompt: str, default: Optional[str] = None) -> str:
    """
    Read a line of input; Ctrl+C exits cleanly without traceback.
    """
    from lib.core.interrupt import exit_clean

    suffix = f" [{default}]" if default is not None else ""
    try:
        value = input(colored(f"{prompt}{suffix}: ", "yellow")).strip()
    except (KeyboardInterrupt, EOFError):
        exit_clean()
    if not value and default is not None:
        return default
    return value


def ask_continue_scanning() -> bool:
    """Ask whether to continue after a finding; Ctrl+C exits cleanly."""
    choice = prompt_line("\n[?] Vulnerability found. Continue scanning? [y/N]", "n").lower()
    return choice == "y"


def confirm_action(message: str, default: bool = True) -> bool:
    """
    Ask user for confirmation.
    
    Args:
        message: Confirmation message
        default: Default value if user just presses Enter
        
    Returns:
        User's choice
    """
    from lib.core.interrupt import exit_clean

    suffix = "[Y/n]" if default else "[y/N]"
    try:
        response = input(colored(f"{message} {suffix}: ", "yellow")).strip().lower()
    except (KeyboardInterrupt, EOFError):
        exit_clean()

    if not response:
        return default

    return response in ('y', 'yes')
