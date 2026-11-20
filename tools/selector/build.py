"""Build only the sampling role from the registered offline Python image."""
import json
import shutil
import tempfile
from pathlib import Path

from tools.frontend.build import LOCK, ROOT, build, docker_id
from varyroot.selector import TAG


def image():
    base = json.loads(LOCK.read_bytes())["base_image"]
    if docker_id("python:3.13-slim") != base:
        raise ValueError("offline Python image differs from registered digest")
    with tempfile.TemporaryDirectory() as directory:
        context = Path(directory)
        shutil.copyfile(ROOT / "varyroot/selector_container.py", context / "selector_container.py")
        (context / "Dockerfile").write_text(
            "FROM " + base + "\nCOPY selector_container.py /opt/selector/selector_container.py\n"
            "USER 65534:65534\nWORKDIR /input\n")
        build(context, TAG)


if __name__ == "__main__":
    image()

