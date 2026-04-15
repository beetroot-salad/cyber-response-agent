"""Allows `python -m invlang` when scripts/ is on the path."""
import sys
from .cli import main

sys.exit(main())
