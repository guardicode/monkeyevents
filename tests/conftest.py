import sys
from pathlib import Path

MONKEYEVENTS_BASE_PATH = str(Path(__file__).parent.parent.parent)
sys.path.insert(0, MONKEYEVENTS_BASE_PATH)
