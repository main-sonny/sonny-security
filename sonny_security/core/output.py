"""Terminal presentation and JSON reporting."""
import json
import os
import sys

BANNER = r"""
   ____   ___  _   _ _   _ __   __
  / ___| / _ \| \ | | \ | |\ \ / /
  \___ \| | | |  \| |  \| | \ V /
   ___) | |_| | |\  | |\  |  | |
  |____/ \___/|_| \_|_| \_|  |_|
  +---------------------------------------+
  | SECURITY TOOLKIT   /   Developer Sonny |
  +---------------------------------------+
"""

def show(data, as_json=False):
    if not as_json:
        color = sys.stdout.isatty() and 'NO_COLOR' not in os.environ
        print(('\033[36m' + BANNER + '\033[0m') if color else BANNER)
    # JSON escaping prevents terminal control characters in remote data/filenames.
    print(json.dumps(data, indent=2, ensure_ascii=True))
