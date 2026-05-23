
#!/usr/bin/env python3
"""Legacy compatibility wrapper for the verification script.

This file previously contained the verification script `test_story14.py`.
It has been renamed to `verify_models.py` for a more professional name.
Keeping this tiny wrapper ensures old references won't break immediately.
"""

import sys
from pathlib import Path

msg = (
	"The verification script has been renamed to 'benchmark/verify_models.py'.\n"
	"Please run: python3 benchmark/verify_models.py\n"
)

if __name__ == "__main__":
	sys.stdout.write(msg)
	# Exit with non-zero so automated scripts detect that they should update
	sys.exit(2)

