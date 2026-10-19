"""Run one or more headless Android emulators for android_browser_evaluator.

Several clauditors on one machine each need their own emulator. All instances
boot the same AVD in ``-read-only`` mode (the emulator refuses a second
writable instance of an AVD), each on its own console port, so they appear to
adb as ``emulator-5554``, ``emulator-5556``, ... Hand each clauditor one of
those serials through ``ANDROID_SERIAL``.

Hardware acceleration is required: without KVM an ASAN GeckoView child
process cannot attach within Android's process-start timeout and is killed,
so pages never render. The ``start`` command refuses to run unaccelerated
unless told to.
"""

from __future__ import annotations

import contextlib
import fcntl
import os
import re
import signal
import socket
import subprocess
import sys
import tempfile
import time
from argparse import ArgumentParser, Namespace
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

__all__ = ["adb_path", "emulator_args", "emulator_path", "free_console_ports", "main"]

SDK_ROOT_ENV = "ANDROID_SDK_ROOT"
DEFAULT_SDK_ROOT = Path.home() / ".mozbuild" / "android-sdk-linux"
AVD_HOME_ENV = "ANDROID_AVD_HOME"
# Where mach bootstrap creates its AVDs; the emulator only looks there when told.
DEFAULT_AVD_HOME = Path.home() / ".mozbuild" / "android-device" / "avd"
DEFAULT_AVD = "mozemulator-android34-x86_64"
# ASAN processes need several times the memory of regular ones; with 4 GB the
# low memory killer takes Gecko's child processes out during longer runs.
DEFAULT_MEMORY_MB = 8192
DEFAULT_CORES = 4
# Emulator console ports are even numbers in this range; adb derives the
# serial from the console port (emulator-<port>).
CONSOLE_PORT_MIN = 5554
CONSOLE_PORT_MAX = 5682
BOOT_TIMEOUT = 300
# Evaluator-side auto-restart: when set, android_browser_evaluator boots its own
# device (ANDROID_SERIAL) if it has vanished, then retries once.
AUTOSTART_ENV = "ANDROID_AUTOSTART_EMULATOR"
LOG_DIR_ENV = "ANDROID_EMULATOR_LOG_DIR"
BOOT_LOCK = Path(tempfile.gettempdir()) / "fx-audit-emulator-boot.lock"


def sdk_root() -> Path:
    """The Android SDK, from ANDROID_SDK_ROOT or mach bootstrap's default location."""
    return Path(os.environ.get(SDK_ROOT_ENV) or DEFAULT_SDK_ROOT)


def emulator_path() -> Path:
    """Path of the emulator launcher."""
    return sdk_root() / "emulator" / "emulator"


def adb_path() -> Path:
    """Path of adb."""
    return sdk_root() / "platform-tools" / "adb"


def _emulator_env() -> dict[str, str]:
    """Environment for the emulator: point it at mach's AVDs unless already told."""
    env = dict(os.environ)
    if not env.get(AVD_HOME_ENV) and DEFAULT_AVD_HOME.is_dir():
        env[AVD_HOME_ENV] = str(DEFAULT_AVD_HOME)
    return env


def _port_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True


def free_console_ports(count: int, first: int = CONSOLE_PORT_MIN) -> list[int]:
    """Pick ``count`` free console ports, each with its adb port (port + 1) free too."""
    ports: list[int] = []
    port = first if first % 2 == 0 else first + 1
    while len(ports) < count and port <= CONSOLE_PORT_MAX:
        if _port_free(port) and _port_free(port + 1):
            ports.append(port)
        port += 2
    if len(ports) < count:
        raise RuntimeError(f"Only {len(ports)} free emulator console ports found")
    return ports


def emulator_args(
    avd: str, port: int, memory_mb: int, cores: int, accelerated: bool
) -> list[str]:
    """Command line for one headless instance.

    ``-read-only`` lets several instances share the AVD (each gets a
    throwaway copy of userdata); ``-no-snapshot`` makes every boot cold, which
    is what the install-hash check in the evaluator expects.
    """
    return [
        str(emulator_path()),
        "-avd",
        avd,
        "-read-only",
        "-port",
        str(port),
        "-no-window",
        "-no-audio",
        "-no-boot-anim",
        "-no-snapshot",
        "-no-metrics",
        "-gpu",
        "swiftshader_indirect",
        "-memory",
        str(memory_mb),
        "-cores",
        str(cores),
        "-selinux",
        "permissive",
        "-skip-adb-auth",
        "-prop",
        "ro.test_harness=true",
        "-accel",
        "on" if accelerated else "off",
    ]


def _acceleration_available() -> bool:
    if not Path("/dev/kvm").exists():
        return False
    result = subprocess.run(
        [str(emulator_path()), "-accel-check"],
        capture_output=True,
        text=True,
        check=False,
    )
    return "is installed and usable" in result.stdout


def _adb(serial: str, *args: str, timeout: int = 30) -> str | None:
    result = subprocess.run(
        [str(adb_path()), "-s", serial, *args],
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout,
    )
    return result.stdout.strip() if result.returncode == 0 else None


def _wait_for_boot(serial: str, timeout: int) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if (
                _adb(serial, "shell", "getprop", "sys.boot_completed", timeout=15)
                == "1"
            ):
                return True
        except subprocess.TimeoutExpired:
            pass
        time.sleep(3)
    return False


def boot_serial(
    serial: str,
    *,
    avd: str = DEFAULT_AVD,
    timeout: int = BOOT_TIMEOUT,
    log_dir: Path | None = None,
) -> bool:
    """Boot one ``-read-only`` instance of *avd* on the console port *serial*
    names, and wait for it to finish booting.

    Boots are serialized across processes with a file lock: several
    ``-read-only`` instances starting at once race on the AVD's qemu image
    locks and some die. If another process booted the device meanwhile, this
    returns True without starting a second instance.

    Returns:
        True once ``sys.boot_completed`` is 1, False on timeout.
    """
    match = re.fullmatch(r"emulator-(\d+)", serial)
    if not match:
        raise ValueError(f"not an emulator serial: {serial!r}")
    port = int(match.group(1))
    if not _acceleration_available():
        raise RuntimeError(
            "No hardware acceleration (KVM); refusing to boot an ASan emulator in "
            "software mode"
        )
    log_dir = log_dir or Path(
        os.environ.get(LOG_DIR_ENV) or Path(tempfile.gettempdir()) / "fx-audit-emulator"
    )
    log_dir.mkdir(parents=True, exist_ok=True)
    with BOOT_LOCK.open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            if _adb(serial, "get-state") == "device":
                return True
            with (log_dir / f"{serial}.log").open("ab") as log_file:
                subprocess.Popen(
                    emulator_args(avd, port, DEFAULT_MEMORY_MB, DEFAULT_CORES, True),
                    stdout=log_file,
                    stderr=subprocess.STDOUT,
                    stdin=subprocess.DEVNULL,
                    env=_emulator_env(),
                    start_new_session=True,
                )
            return _wait_for_boot(serial, timeout)
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


def _kill_port_processes(port: int) -> None:
    """SIGKILL any qemu instance serving console *port* (fallback for a wedged
    emulator that ignores ``adb emu kill``)."""
    needle = f"-port\0{port}\0"
    for proc in Path("/proc").iterdir():
        if not proc.name.isdigit():
            continue
        try:
            cmdline = (proc / "cmdline").read_bytes().decode(errors="replace")
        except OSError:
            continue
        if "qemu-system" in cmdline and needle in cmdline:
            with contextlib.suppress(OSError):
                os.kill(int(proc.name), signal.SIGKILL)


def restart_serial(
    serial: str,
    *,
    avd: str = DEFAULT_AVD,
    timeout: int = BOOT_TIMEOUT,
    log_dir: Path | None = None,
) -> bool:
    """Kill the instance *serial* names, even one that still answers adb, and
    boot a fresh one on the same console port.

    Needed when the guest is wedged rather than gone: a still-"device" emulator
    whose package service has died fails every install until it is replaced,
    and :func:`boot_serial` alone would see it as already up.
    """
    match = re.fullmatch(r"emulator-(\d+)", serial)
    if not match:
        raise ValueError(f"not an emulator serial: {serial!r}")
    port = int(match.group(1))
    with contextlib.suppress(subprocess.TimeoutExpired):
        _adb(serial, "emu", "kill", timeout=30)
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline and _adb(serial, "get-state") == "device":
        time.sleep(2)
    if _adb(serial, "get-state") == "device":
        _kill_port_processes(port)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and _adb(serial, "get-state") == "device":
            time.sleep(2)
    if _adb(serial, "get-state") == "device":
        return False
    return boot_serial(serial, avd=avd, timeout=timeout, log_dir=log_dir)


def _emulator_serials() -> list[str]:
    result = subprocess.run(
        [str(adb_path()), "devices"], capture_output=True, text=True, check=False
    )
    return [
        line.split()[0]
        for line in result.stdout.splitlines()
        if line.startswith("emulator-")
    ]


def start(args: Namespace) -> int:
    """Boot ``args.count`` instances and print their serials once booted."""
    accelerated = _acceleration_available()
    if not accelerated and not args.allow_software:
        print(
            "No usable KVM acceleration (/dev/kvm); refusing to start a software "
            "emulated device, which cannot run ASAN GeckoView. Pass "
            "--allow-software to override.",
            file=sys.stderr,
        )
        return 1
    args.log_dir.mkdir(parents=True, exist_ok=True)
    ports = free_console_ports(args.count, args.base_port)
    serials = []
    for port in ports:
        serial = f"emulator-{port}"
        log = args.log_dir / f"{serial}.log"
        with log.open("wb") as log_file:
            subprocess.Popen(
                emulator_args(args.avd, port, args.memory, args.cores, accelerated),
                stdout=log_file,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                start_new_session=True,
                env=_emulator_env(),
            )
        serials.append(serial)
        print(f"starting {serial} (log: {log})", file=sys.stderr)
    failed = 0
    for serial in serials:
        if _wait_for_boot(serial, args.boot_timeout):
            print(serial)
        else:
            failed += 1
            print(f"{serial} did not boot within {args.boot_timeout}s", file=sys.stderr)
            log = args.log_dir / f"{serial}.log"
            for line in log.read_text(errors="replace").splitlines():
                if line.startswith("ERROR"):
                    print(f"  {line}", file=sys.stderr)
    if serials and not failed:
        print(
            "Each clauditor needs its own device: export ANDROID_SERIAL=<serial> "
            "before starting it.",
            file=sys.stderr,
        )
    return 1 if failed else 0


def stop(args: Namespace) -> int:
    """Shut down the given emulators, or all of them."""
    serials = args.serials or _emulator_serials()
    for serial in serials:
        _adb(serial, "emu", "kill")
        print(f"stopped {serial}")
    return 0


def list_devices(_args: Namespace) -> int:
    """Print the serials of running emulators."""
    for serial in _emulator_serials():
        print(serial)
    return 0


def parse_args(argv: Sequence[str] | None = None) -> Namespace:
    """Argument parsing for the ``fx-audit-android-emulator`` CLI."""
    parser = ArgumentParser(description="Manage headless Android emulators.")
    sub = parser.add_subparsers(dest="command", required=True)

    start_parser = sub.add_parser("start", help="boot emulator instances")
    start_parser.add_argument("--count", type=int, default=1, help="instances to boot")
    start_parser.add_argument("--avd", default=DEFAULT_AVD, help="AVD name")
    start_parser.add_argument(
        "--memory", type=int, default=DEFAULT_MEMORY_MB, help="guest RAM in MB"
    )
    start_parser.add_argument("--cores", type=int, default=DEFAULT_CORES)
    start_parser.add_argument(
        "--base-port",
        type=int,
        default=CONSOLE_PORT_MIN,
        help="first console port to try (even, 5554-5682)",
    )
    start_parser.add_argument(
        "--boot-timeout", type=int, default=BOOT_TIMEOUT, help="seconds per instance"
    )
    start_parser.add_argument(
        "--log-dir",
        type=Path,
        default=Path.cwd() / "emulator-logs",
        help="where each instance's console output goes",
    )
    start_parser.add_argument(
        "--allow-software",
        action="store_true",
        help="start without KVM (slow; ASAN GeckoView will not work)",
    )
    start_parser.set_defaults(func=start)

    stop_parser = sub.add_parser("stop", help="shut emulators down")
    stop_parser.add_argument("serials", nargs="*", help="default: all emulators")
    stop_parser.set_defaults(func=stop)

    list_parser = sub.add_parser("list", help="print running emulator serials")
    list_parser.set_defaults(func=list_devices)

    args = parser.parse_args(argv)
    if args.command == "start":
        if args.count < 1:
            parser.error("--count must be at least 1")
        if not emulator_path().is_file():
            parser.error(f"emulator not found at {emulator_path()}; set {SDK_ROOT_ENV}")
    return args


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point for ``fx-audit-android-emulator``."""
    args = parse_args(argv)
    result: int = args.func(args)
    return result


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
