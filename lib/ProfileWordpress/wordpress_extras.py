# Copyright (c) 2026 waymap developers
# See the file 'LICENSE' for copying permission.

"""WordPress extras scan module - delegates to consolidated WordPress scanner."""

from typing import List

from lib.ProfileWordpress.profile_wordpress import perform_wordpress_scan


def perform_wordpress_extras_scan(
    urls: List[str],
    thread_count: int = 1,
    no_prompt: bool = False,
    verbose: bool = False,
) -> None:
    """Run the consolidated WordPress scanner.

    This is the entry point called by scanner.py for the ``wordpress-extras``
    scan type. It delegates entirely to :func:`perform_wordpress_scan`.
    """
    perform_wordpress_scan(
        crawled_urls=urls,
        thread_count=thread_count,
        no_prompt=no_prompt,
        verbose=verbose,
    )
