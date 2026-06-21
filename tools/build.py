#!/usr/bin/env python3
import argparse
import shutil
# Used only with a fixed Python executable and allowlisted local scripts.
import subprocess  # nosec B404
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"
PACKAGE_DIR = DIST / "web-safe"
PACKAGE_ZIP = DIST / "web-safe.zip"
EXTENSION_PATHS = [
    "manifest.json",
    "icons",
    "popup",
    "src",
    "README.md",
]
ALLOWED_BUILD_SCRIPTS = {
    "tools/update_public_suffix_list.py",
    "tools/train_site_model.py",
    "tools/train_url_model.py",
}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip-psl", action="store_true")
    parser.add_argument("--skip-train", action="store_true")
    parser.add_argument("--skip-site-train", action="store_true")
    parser.add_argument("--positive-limit", type=int, default=8000)
    parser.add_argument("--negative-limit", type=int, default=8000)
    parser.add_argument("--epochs", type=int, default=120)
    args = parser.parse_args()

    if not args.skip_psl:
        run([sys.executable, "tools/update_public_suffix_list.py"])

    if not args.skip_train:
        run(
            [
                sys.executable,
                "tools/train_url_model.py",
                "--positive-limit",
                str(args.positive_limit),
                "--negative-limit",
                str(args.negative_limit),
                "--epochs",
                str(args.epochs),
            ]
        )

        if not args.skip_site_train:
            run(
                [
                    sys.executable,
                    "tools/train_site_model.py",
                    "--positive-limit",
                    str(args.positive_limit),
                    "--negative-limit",
                    str(args.negative_limit),
                    "--epochs",
                    str(args.epochs),
                ]
            )

    prepare_dist()
    copy_extension_files()
    create_zip()

    print(f"build ready: {PACKAGE_DIR}")
    print(f"zip ready: {PACKAGE_ZIP}")


def run(command):
    validate_build_command(command)
    print("$ " + " ".join(command))
    # Command is allowlisted and shell=False by default.
    subprocess.run(command, cwd=ROOT, check=True)  # nosec B603


def validate_build_command(command):
    if not command or Path(command[0]).resolve() != Path(sys.executable).resolve():
        raise RuntimeError("Build script can only execute the current Python interpreter.")

    if len(command) < 2 or command[1] not in ALLOWED_BUILD_SCRIPTS:
        raise RuntimeError(f"Build command is not allowlisted: {' '.join(command)}")


def prepare_dist():
    DIST.mkdir(exist_ok=True)
    assert_inside_dist(PACKAGE_DIR)
    assert_inside_dist(PACKAGE_ZIP)

    if PACKAGE_DIR.exists():
        shutil.rmtree(PACKAGE_DIR)

    if PACKAGE_ZIP.exists():
        PACKAGE_ZIP.unlink()

    PACKAGE_DIR.mkdir(parents=True)


def copy_extension_files():
    for relative_path in EXTENSION_PATHS:
        source = ROOT / relative_path
        target = PACKAGE_DIR / relative_path

        if source.is_dir():
            shutil.copytree(
                source,
                target,
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
            )
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)


def create_zip():
    with zipfile.ZipFile(PACKAGE_ZIP, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in PACKAGE_DIR.rglob("*"):
            if path.is_file():
                archive.write(path, path.relative_to(PACKAGE_DIR))


def assert_inside_dist(path):
    resolved_path = path.resolve()
    resolved_dist = DIST.resolve()
    if not resolved_path.is_relative_to(resolved_dist):
        raise RuntimeError(f"Refusing to modify path outside dist: {path}")


if __name__ == "__main__":
    main()
