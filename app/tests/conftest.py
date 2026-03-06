"""Ensure the workspace root is on sys.path for app imports."""
import sys
from pathlib import Path

# Add workspace root so 'from app.xxx import ...' works
workspace_root = str(Path(__file__).parent.parent.parent)
if workspace_root not in sys.path:
    sys.path.insert(0, workspace_root)
