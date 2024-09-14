import datetime

# ANSI color codes
class Colors:
    LIGHT_GREEN = "\033[92m"
    DARK_GREEN = "\033[32m"
    WHITE_BOLD = "\033[1m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BLUE = "\033[94m"
    RESET = "\033[0m"

def log_message(message, level="info"):
    """
    Log a message to the console with color formatting.

    Args:
        message (str): The message to log.
        level (str): The level of the log (info, success, warning, error, critical).
    """
    # Get the current time in HH:MM:SS format
    current_time = datetime.datetime.now().strftime("%H:%M:%S")

    # Format the message based on the log level
    if level == "info":
        formatted_message = f"{Colors.LIGHT_GREEN}[INFO] {Colors.RESET}{message}"
    elif level == "success":
        formatted_message = f"{Colors.DARK_GREEN}[SUCCESS] {Colors.RESET}{message}"
    elif level == "warning":
        formatted_message = f"{Colors.YELLOW}[WARNING] {Colors.RESET}{message}"
    elif level == "error":
        formatted_message = f"{Colors.WHITE_BOLD}[ERROR] {Colors.RESET}{message}"
    elif level == "critical":
        formatted_message = f"{Colors.RED}[CRITICAL] {Colors.RESET}{message}"
    else:
        formatted_message = f"{Colors.WHITE_BOLD}[LOG] {Colors.RESET}{message}"

    # Add the timestamp in blue
    log_output = f"{Colors.BLUE}{current_time}{Colors.RESET} {formatted_message}"
    
    # Print the formatted message
    print(log_output)
