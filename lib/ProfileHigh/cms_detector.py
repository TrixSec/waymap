# Copyright (c) 2024 waymap developers
# See the file 'LICENSE' for copying permission.

"""CMS Detection Module for ProfileHigh."""

# This is a duplicate of ProfileCritical/cms_detector.py
# Import from there to avoid code duplication

from lib.ProfileCritical.cms_detector import detect_cms, detect_wordpress, detect_drupal

__all__ = ['detect_cms', 'detect_wordpress', 'detect_drupal']