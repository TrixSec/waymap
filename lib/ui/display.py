# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.

"""UI components and display utilities."""

import time
import sys
from typing import List, Tuple, Optional


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
    print(colored(char * length, color))


def print_header(text: str, color: str = "yellow", top_padding: int = 1, bottom_padding: int = 1) -> None:
    """Print a formatted header."""
    if top_padding:
        print()
    border = "═" * (len(text) + 2)
    print(colored(f"╔{border}╗", color))
    print(colored(f"║ {text.upper()} ║", color))
    print(colored(f"╚{border}╝", color))
    if bottom_padding:
        print()


def print_status(message: str, status_type: str = "info", icon: Optional[str] = None) -> None:
    """
    Print status messages with colored icons.
    
    Args:
        message: Message to display
        status_type: Type of status (info, success, warning, error, debug)
        icon: Optional custom icon
    """
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
    print(colored(f"[{icon_char}] {message}", color))


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
    banner = r"""
╔══════════════════════════════════════════════════════════════════╗
║ ██╗    ██╗ █████╗ ██╗   ██╗███╗   ███╗ █████╗ ██████╗            ║
║ ██║    ██║██╔══██╗╚██╗ ██╔╝████╗ ████║██╔══██╗██╔══██╗           ║
║ ██║ █╗ ██║███████║ ╚████╔╝ ██╔████╔██║███████║██████╔╝           ║
║ ██║███╗██║██╔══██║  ╚██╔╝  ██║╚██╔╝██║██╔══██║██╔═══╝            ║
║ ╚███╔███╔╝██║  ██║   ██║   ██║ ╚═╝ ██║██║  ██║██║                ║
║  ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝                ║
║                  Fastest Optimized Web Scanner                   ║
╚══════════════════════════════════════════════════════════════════╝
    """
    print(colored(banner, 'cyan'))
    print_separator("═", "cyan", 70)
    from lib.core.config import get_config
    cfg = get_config()
    print(colored(f"Version: {cfg.VERSION:>50}", 'yellow'))
    print(colored(f"Author:  {cfg.AUTHOR:>50}", 'yellow'))
    print(colored(f"{cfg.COPYRIGHT:>70}", 'yellow'))
    print_separator("═", "cyan", 70)
    print()


def clear_line() -> None:
    """Clear the current line."""
    print("\r" + " " * 80 + "\r", end="")
    sys.stdout.flush()


def confirm_action(message: str, default: bool = True) -> bool:
    """
    Ask user for confirmation.
    
    Args:
        message: Confirmation message
        default: Default value if user just presses Enter
        
    Returns:
        User's choice
    """
    suffix = "[Y/n]" if default else "[y/N]"
    response = input(colored(f"{message} {suffix}: ", "yellow")).strip().lower()
    
    if not response:
        return default
    
    return response in ('y', 'yes')
