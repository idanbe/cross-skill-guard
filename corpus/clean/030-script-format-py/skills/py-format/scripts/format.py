import subprocess
import sys

subprocess.run(["ruff", "format", *sys.argv[1:]], check=True)
