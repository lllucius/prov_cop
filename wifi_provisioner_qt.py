#!/usr/bin/env python3
"""ESP32 Wi-Fi Provisioner — accessible PySide6/Qt 6 desktop application.

This is the desktop counterpart to ``index.html``. It speaks exactly the
same wire protocol to the ESP-IDF ``provisioner`` component over a serial
port:

    Host  -> ESP32 :  <<PROV?>>\\n               (attention probe)
    ESP32 -> Host  :  <<PROV!>>\\n               (ready)
    ESP32 -> Host  :  <<PROV:ID name_b64>>\\n    (optional device name)
    Host  -> ESP32 :  <<PROV:SET ssid_b64 pass_b64 crc16>>\\n
    ESP32 -> Host  :  <<PROV:OK>> or <<PROV:ERR reason>>

Design goals
------------
* **Single module.** Everything (UI, worker, protocol, palette) lives here.
* **Python >= 3.12.**
* **Accessibility first.** Primary targets are JAWS and Windows. Every
  control has a real ``QLabel`` with a buddy and an access key (``&``
  mnemonic). Tab order is set explicitly. Information-only fields
  (status, connected device name, serial log) are implemented as
  *read-only* ``QLineEdit`` / ``QPlainTextEdit`` widgets so they appear
  in the keyboard tab order, can be navigated and copied like any other
  text field, and are reliably read by screen readers. Status changes
  emit a Qt ``QAccessible.Alert`` event so JAWS announces them.
* **OS light/dark theme.** The application palette follows
  ``QStyleHints.colorScheme()`` and updates live when the user changes
  the system theme.

Dependencies
------------
* ``PySide6`` (Qt 6.5 or newer is recommended for ``colorScheme()``)
* ``pyserial``

Run with::

    python3 wifi_provisioner_qt.py
"""

from __future__ import annotations

import base64
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional

import serial
from serial.tools import list_ports

from PySide6 import QtCore, QtGui, QtWidgets
from PySide6.QtCore import Qt, QThread, Signal


# --------------------------------------------------------------------------- #
# Protocol constants — must stay in sync with index.html and provisioner_proto
# --------------------------------------------------------------------------- #

BAUD = 115200
PROBE = b"<<PROV?>>\n"
READY_FRAME = b"<<PROV!>>"
READY_RE = re.compile(re.escape(READY_FRAME))
ID_RE = re.compile(rb"<<PROV:ID\s+([A-Za-z0-9+/=]+)>>")
RESULT_RE = re.compile(rb"<<PROV:(OK|ERR)(?:\s+([^>\r\n]*))?>>")
NO_REASON_GIVEN = "(no reason given)"

PROBE_INTERVAL_S = 0.5      # time to wait for a READY between probes
ATTENTION_TIMEOUT_S = 8.0   # total time to wait for the first READY
ID_GRACE_S = 0.2            # grace period to receive the optional ID frame
RESULT_TIMEOUT_S = 90.0     # max time to wait for OK/ERR after SET (matches
                            # the web page; the firmware retries Wi-Fi up to
                            # 5x before reporting auth_or_unreachable, which
                            # can legitimately take ~20s+).

DEVICE_NAME_MAX = 64        # matches PROV_PROTO_MAX_NAME_LEN in firmware
SSID_MAX_BYTES = 32         # IEEE 802.11 SSID limit
PASS_MAX_BYTES = 63         # WPA passphrase limit
SERIAL_BUFFER_CAP = 8192    # protects against runaway input
SERIAL_BUFFER_TRIM = 4096   # bytes kept when the buffer is trimmed


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #

def crc16_ccitt_false(data: bytes) -> int:
    """Compute CRC-16/CCITT-FALSE.

    Polynomial ``0x1021``, initial value ``0xFFFF``, no input/output
    reflection, no XOR-out. This matches the web page implementation and
    the firmware's expectation for the ``<<PROV:SET ...>>`` checksum.

    :param data: bytes to checksum.
    :returns: CRC value in the range 0..65535.
    """
    crc = 0xFFFF
    for byte in data:
        crc ^= (byte & 0xFF) << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc


def sanitise_device_name(raw: str) -> str:
    """Strip control characters and clamp the length of a device name.

    The ESP32 advertises its display name in a ``<<PROV:ID ...>>`` frame.
    The payload is attacker-controllable in a hostile-firmware scenario,
    so we strip C0 / DEL bytes (which would let a malicious device emit
    ANSI escape sequences or otherwise smuggle UI changes) and clamp the
    length to :data:`DEVICE_NAME_MAX` characters.
    """
    if not raw:
        return ""
    cleaned = re.sub(r"[\x00-\x1f\x7f]", "", raw)
    if len(cleaned) > DEVICE_NAME_MAX:
        cleaned = cleaned[:DEVICE_NAME_MAX]
    return cleaned.strip()


class _Cancelled(Exception):
    """Internal sentinel raised inside the worker thread when cancelled."""


@dataclass
class PortInfo:
    """A serial port discovered on the host, in display-friendly form."""
    device: str
    description: str

    @property
    def label(self) -> str:
        """Human-readable label combining device path and description."""
        if self.description and self.description.lower() != "n/a":
            return f"{self.device} \u2014 {self.description}"
        return self.device


def list_serial_ports() -> list[PortInfo]:
    """Return all serial ports the OS knows about, sorted by device name."""
    ports = [PortInfo(p.device, p.description or "") for p in list_ports.comports()]
    ports.sort(key=lambda p: p.device)
    return ports


def list_wifi_ssids() -> list[str]:
    """Return visible Wi-Fi network names, best-effort and de-duplicated."""
    if sys.platform.startswith("win"):
        ssids = _scan_windows_ssids()
    elif sys.platform == "darwin":
        ssids = _scan_macos_ssids()
    else:
        ssids = _scan_linux_ssids()
    return sorted({ssid for ssid in ssids if ssid}, key=str.casefold)


def _run_scan_command(args: list[str]) -> str:
    """Run an OS Wi-Fi scan command and return stdout.

    Returns ``""`` when the command is unavailable, times out, cannot be
    launched, or exits with a non-zero status.
    """
    try:
        proc = subprocess.run(
            args,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    if proc.returncode != 0:
        return ""
    return proc.stdout


def _scan_windows_ssids() -> list[str]:
    """List visible SSIDs using Windows ``netsh``."""
    if shutil.which("netsh") is None:
        return []
    output = _run_scan_command(["netsh", "wlan", "show", "networks", "mode=bssid"])
    ssids: list[str] = []
    for line in output.splitlines():
        match = re.match(r"\s*SSID\s+\d+\s*:\s*(.*?)\s*$", line)
        if match:
            ssids.append(match.group(1).strip())
    return ssids


def _scan_macos_ssids() -> list[str]:
    """List visible SSIDs using macOS's airport scanner."""
    airport = (
        "/System/Library/PrivateFrameworks/Apple80211.framework"
        "/Versions/Current/Resources/airport"
    )
    if not os.path.exists(airport):
        return []
    output = _run_scan_command([airport, "-s"])
    ssids: list[str] = []
    bssid_re = re.compile(r"\s+(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\s+")
    for line in output.splitlines()[1:]:
        match = bssid_re.search(line)
        if match:
            ssids.append(line[: match.start()].strip())
    return ssids


def _scan_linux_ssids() -> list[str]:
    """List visible SSIDs using NetworkManager's ``nmcli`` when available."""
    if shutil.which("nmcli") is None:
        return []
    output = _run_scan_command(
        ["nmcli", "--terse", "--fields", "SSID", "dev", "wifi", "list", "--rescan", "yes"]
    )
    ssids: list[str] = []
    for line in output.splitlines():
        ssid = _unescape_nmcli_field(line).strip()
        if ssid:
            ssids.append(ssid)
    return ssids


def _unescape_nmcli_field(text: str) -> str:
    """Decode backslash escapes used by ``nmcli --terse`` fields."""
    chars: list[str] = []
    escaped = False
    for ch in text:
        if escaped:
            chars.append(ch)
            escaped = False
        elif ch == "\\":
            escaped = True
        else:
            chars.append(ch)
    if escaped:
        chars.append("\\")
    return "".join(chars)


# --------------------------------------------------------------------------- #
# Worker — performs the provisioning protocol off the GUI thread
# --------------------------------------------------------------------------- #

class ProvisionWorker(QThread):
    """Run the provisioning protocol against an ESP32 in a background thread.

    All UI updates are emitted as Qt signals so they are auto-marshalled
    back to the GUI thread.

    Signals:
        statusChanged(str): a human-readable status message.
        deviceName(str):    sanitized device name from a ``<<PROV:ID>>`` frame.
        logLine(str, str):  ``(direction, text)`` where ``direction`` is
                             ``"TX"`` or ``"RX"``. ``text`` may be a
                             partial line (RX arrives in chunks).
        failed(str):        terminal failure with a user-facing message.
        succeeded():        terminal success.
    """

    statusChanged = Signal(str)
    deviceName = Signal(str)
    logLine = Signal(str, str)
    failed = Signal(str)
    succeeded = Signal()

    def __init__(self, port_name: str, ssid: str, password: str,
                 parent: Optional[QtCore.QObject] = None) -> None:
        """Configure the worker; nothing is opened until :meth:`start`."""
        super().__init__(parent)
        self._port_name = port_name
        self._ssid = ssid
        self._password = password
        self._cancel = threading.Event()

    # -- public control surface -------------------------------------------------
    def cancel(self) -> None:
        """Request graceful cancellation. Safe to call from any thread.

        The worker checks the flag between protocol steps and between
        each short ``read()`` slice, so cancellation typically takes
        less than 250 ms to surface as a ``failed`` signal.
        """
        self._cancel.set()

    # -- QThread entry point ---------------------------------------------------
    def run(self) -> None:  # noqa: D401 — QThread API
        """Open the port, run the protocol, and emit a terminal signal."""
        try:
            self._run()
        except _Cancelled:
            self.failed.emit("Cancelled.")
        except Exception as exc:  # pylint: disable=broad-except
            # Any unexpected exception is surfaced as a user-facing error.
            self.failed.emit(str(exc) or exc.__class__.__name__)

    # -- protocol implementation -----------------------------------------------
    def _run(self) -> None:
        """Open the serial port and execute the provisioning sequence."""
        self.statusChanged.emit(f"Opening serial port {self._port_name} ...")
        try:
            # Create the Serial object without a port so it is not opened
            # immediately; we need to set dtr/rts before the physical open.
            ser = serial.Serial(
                baudrate=BAUD,
                bytesize=serial.EIGHTBITS,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE,
                timeout=0.1,
                write_timeout=2.0,
            )
            # Deassert DTR and RTS before opening. pyserial applies these
            # states at open() time, so setting them here prevents the brief
            # assertion that would otherwise trigger the ESP32 autoreset
            # circuit wired to the DTR/RTS lines on most dev boards.
            ser.dtr = False
            ser.rts = False
            ser.port = self._port_name
            ser.open()
            # Discard any bytes that were left in the OS receive buffer from a
            # previous session. Without this, stale <<PROV:ERR>> or <<PROV:OK>>
            # frames can end up in buf during the attention phase and cause the
            # result-wait fast-path to match them before any real data arrives.
            try:
                ser.reset_input_buffer()
            except serial.SerialException:
                pass
        except serial.SerialException as exc:
            raise RuntimeError(
                f"Could not open serial port {self._port_name}: {exc}"
            ) from exc

        try:
            self._provision(ser)
        finally:
            try:
                ser.close()
            except Exception:  # pylint: disable=broad-except
                pass
        self.succeeded.emit()

    def _provision(self, ser: serial.Serial) -> None:
        """Execute the full provisioning protocol on an open serial port."""
        buf = bytearray()

        # --- Attention phase: probe until we see READY, or time out ----------
        self.statusChanged.emit(
            "Connected to serial device. Trying to get the ESP32's attention ..."
        )
        ready_seen = False
        deadline = time.monotonic() + ATTENTION_TIMEOUT_S
        while time.monotonic() < deadline:
            self._raise_if_cancelled()
            self._send(ser, PROBE)
            ready_seen = self._wait_for_buffer_match(
                ser,
                buf,
                READY_RE.search,
                PROBE_INTERVAL_S,
            )
            if ready_seen:
                break
        if not ready_seen:
            raise RuntimeError(
                "The ESP32 did not respond. Check that the board is plugged "
                "in, running the provisioning firmware, and not opened by "
                "another program."
            )

        # --- Optional ID frame -----------------------------------------------
        # Some firmware advertises a human-readable name immediately after
        # READY. Wait briefly for it, but do not fail if it never arrives.
        id_match = self._wait_for_buffer_match(
            ser,
            buf,
            ID_RE.search,
            ID_GRACE_S,
        )
        if id_match is not None:
            try:
                decoded = base64.b64decode(id_match.group(1), validate=True)
                name = sanitise_device_name(decoded.decode("utf-8", errors="replace"))
                if name:
                    self.deviceName.emit(name)
            except (ValueError, UnicodeDecodeError):
                # Malformed Base64 / UTF-8: ignore — the name is optional.
                pass

        # --- Send credentials ------------------------------------------------
        # Discard everything accumulated in the software buffer and the OS
        # receive buffer before we send SET. Any bytes that arrived before SET
        # (including stale frames from a prior provisioning attempt or ESP32
        # boot messages) are irrelevant to the result we are about to wait for.
        buf.clear()
        try:
            ser.reset_input_buffer()
        except serial.SerialException:
            pass
        self.statusChanged.emit("ESP32 is ready. Sending Wi-Fi details ...")
        ssid_b64 = base64.b64encode(self._ssid.encode("utf-8")).decode("ascii")
        pass_b64 = base64.b64encode(self._password.encode("utf-8")).decode("ascii")
        crc_input = f"{ssid_b64} {pass_b64}".encode("ascii")
        crc = crc16_ccitt_false(crc_input)
        line = f"<<PROV:SET {ssid_b64} {pass_b64} {crc:04X}>>\n".encode("ascii")
        self._send(ser, line)

        # --- Wait for OK/ERR with a per-second tick --------------------------
        wait_started = time.monotonic()
        last_tick = -1
        while True:
            self._raise_if_cancelled()
            elapsed = time.monotonic() - wait_started
            if elapsed > RESULT_TIMEOUT_S:
                raise RuntimeError(
                    f"The ESP32 did not return a recognisable result within "
                    f"{int(RESULT_TIMEOUT_S)} s."
                )
            sec = int(elapsed)
            if sec != last_tick:
                last_tick = sec
                self.statusChanged.emit(
                    f"Waiting for the ESP32 to confirm ... ({sec} s; this can "
                    f"take up to {int(RESULT_TIMEOUT_S)} s while the ESP32 "
                    f"tries to join the Wi-Fi network)"
                )
            match = self._wait_for_buffer_match(
                ser,
                buf,
                RESULT_RE.search,
                0.25,
            )
            if match is not None:
                kind = match.group(1).decode("ascii", errors="replace")
                if kind == "OK":
                    self.statusChanged.emit(
                        "Success. The ESP32 accepted the Wi-Fi details."
                    )
                    return
                reason_b = match.group(2) or b""
                # The current firmware never emits a bare <<PROV:ERR>> frame:
                # provisioner_proto.c always includes a reason token (at least
                # "fail"). If we see a reason-less ERR here, treat it as a
                # malformed / stale frame and keep waiting for the real result.
                if not reason_b:
                    continue
                reason = reason_b.decode("ascii", errors="replace").strip() or NO_REASON_GIVEN
                raise RuntimeError(f"The ESP32 reported a failure: {reason}")

    # -- I/O primitives --------------------------------------------------------
    def _send(self, ser: serial.Serial, data: bytes) -> None:
        """Write raw bytes to the port and mirror them to the on-screen log."""
        try:
            written = 0
            while written < len(data):
                n = ser.write(data[written:])
                if n == 0:
                    raise RuntimeError("Serial write returned zero bytes.")
                written += n
        except serial.SerialTimeoutException as exc:
            raise RuntimeError("Timed out while writing to the serial port.") from exc
        except serial.SerialException as exc:
            raise RuntimeError(f"Serial write failed: {exc}") from exc
        try:
            ser.flush()
        except Exception:  # pylint: disable=broad-except
            # flush() can raise on some platforms when the device is yanked;
            # the next read() will surface the real error.
            pass
        self.logLine.emit("TX", data.decode("utf-8", errors="replace"))

    @staticmethod
    def _pop_buffer_match(
        buf: bytearray,
        matcher: Callable[[bytes], re.Match[bytes] | None],
    ) -> re.Match[bytes] | None:
        """Consume bytes from ``buf`` through the first matching frame."""
        matched = matcher(bytes(buf))
        if matched is None:
            return None
        del buf[: matched.end()]
        return matched

    def _wait_for_buffer_match(
        self,
        ser: serial.Serial,
        buf: bytearray,
        matcher: Callable[[bytes], re.Match[bytes] | None],
        timeout_s: float,
    ) -> re.Match[bytes] | None:
        """Read until ``matcher`` matches a frame anywhere in ``buf``.

        Mirrors ``index.html`` by searching the whole accumulated RX buffer
        instead of waiting for newline-terminated lines. Non-matching bytes
        ahead of the frame are discarded only once a full frame is found, so
        incidental console chatter and split serial chunks do not block the
        provisioning state machine. Returns ``None`` on timeout.
        """
        match = self._pop_buffer_match(buf, matcher)
        if match is not None:
            return match

        end = time.monotonic() + timeout_s
        while time.monotonic() < end:
            self._raise_if_cancelled()
            chunk = ser.read(256)
            if not chunk:
                continue
            buf.extend(chunk)
            if len(buf) > SERIAL_BUFFER_CAP:
                # Trim from the front to bound memory while keeping enough
                # tail to match any in-flight frame.
                del buf[: len(buf) - SERIAL_BUFFER_TRIM]
            self.logLine.emit("RX", chunk.decode("utf-8", errors="replace"))
            match = self._pop_buffer_match(buf, matcher)
            if match is not None:
                return match
        return None

    def _raise_if_cancelled(self) -> None:
        """Raise :class:`_Cancelled` if cancellation has been requested."""
        if self._cancel.is_set():
            raise _Cancelled()


# --------------------------------------------------------------------------- #
# Theme — follow the OS light/dark color scheme
# --------------------------------------------------------------------------- #

def _make_dark_palette() -> QtGui.QPalette:
    """Build a Fusion-compatible dark palette with high-contrast text.

    We avoid the deepest blacks (which JAWS users with low-vision often
    pair with high contrast settings) and use blue-tinted highlights
    that have a comfortable contrast ratio against both the dark base
    and white highlighted text.
    """
    pal = QtGui.QPalette()
    role = QtGui.QPalette.ColorRole
    group = QtGui.QPalette.ColorGroup

    pal.setColor(role.Window, QtGui.QColor(32, 32, 32))
    pal.setColor(role.WindowText, QtGui.QColor(240, 240, 240))
    pal.setColor(role.Base, QtGui.QColor(20, 20, 20))
    pal.setColor(role.AlternateBase, QtGui.QColor(45, 45, 45))
    pal.setColor(role.Text, QtGui.QColor(240, 240, 240))
    pal.setColor(role.Button, QtGui.QColor(45, 45, 45))
    pal.setColor(role.ButtonText, QtGui.QColor(240, 240, 240))
    pal.setColor(role.ToolTipBase, QtGui.QColor(45, 45, 45))
    pal.setColor(role.ToolTipText, QtGui.QColor(240, 240, 240))
    pal.setColor(role.PlaceholderText, QtGui.QColor(160, 160, 160))
    pal.setColor(role.Highlight, QtGui.QColor(38, 110, 200))
    pal.setColor(role.HighlightedText, QtGui.QColor(255, 255, 255))
    pal.setColor(role.Link, QtGui.QColor(106, 166, 255))
    pal.setColor(role.LinkVisited, QtGui.QColor(170, 130, 220))
    pal.setColor(role.BrightText, QtGui.QColor(255, 80, 80))

    # Disabled-state colours so disabled buttons (e.g. Cancel) remain
    # readable but visibly inactive.
    pal.setColor(group.Disabled, role.Text, QtGui.QColor(127, 127, 127))
    pal.setColor(group.Disabled, role.ButtonText, QtGui.QColor(127, 127, 127))
    pal.setColor(group.Disabled, role.WindowText, QtGui.QColor(127, 127, 127))
    return pal


def apply_color_scheme(app: QtWidgets.QApplication) -> None:
    """Apply a palette matching the current OS light/dark color scheme.

    Uses the Fusion style for consistent palette application across
    platforms. Safe to call repeatedly; intended to also be wired to
    :pyattr:`QStyleHints.colorSchemeChanged` so a runtime theme switch
    on the host OS is reflected immediately.
    """
    app.setStyle("Fusion")
    scheme = app.styleHints().colorScheme()
    if scheme == Qt.ColorScheme.Dark:
        app.setPalette(_make_dark_palette())
    else:
        # Light (or Unknown): fall back to the style's standard light palette.
        app.setPalette(app.style().standardPalette())


# --------------------------------------------------------------------------- #
# Main window
# --------------------------------------------------------------------------- #

class MainWindow(QtWidgets.QMainWindow):
    """Top-level window. Hosts the form, status fields, and the serial log.

    All information-only fields (status, connected device name, log) are
    implemented as read-only edit widgets so they participate in the
    keyboard tab order and can be reviewed and copied by screen-reader
    users.
    """

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("ESP32 Wi-Fi Provisioner")
        self._worker: Optional[ProvisionWorker] = None
        # Tracks whether the next character appended to the log should be
        # prefixed with [TX]/[RX]. Persists across logLine signals because
        # RX chunks may not align with newlines.
        self._log_at_line_start = True

        self._build_ui()
        self.refresh_ssids()
        self.refresh_ports()
        self.resize(680, 720)

    # -- UI construction -------------------------------------------------------
    def _build_ui(self) -> None:
        """Construct all widgets, set accessibility metadata, and tab order."""
        central = QtWidgets.QWidget()
        self.setCentralWidget(central)
        outer = QtWidgets.QVBoxLayout(central)
        outer.setContentsMargins(12, 12, 12, 12)
        outer.setSpacing(8)

        # -- Heading and intro --------------------------------------------- #
        title = QtWidgets.QLabel("ESP32 Wi-Fi Provisioner")
        title_font = title.font()
        title_font.setPointSize(title_font.pointSize() + 4)
        title_font.setBold(True)
        title.setFont(title_font)
        title.setAccessibleName("ESP32 Wi-Fi Provisioner")
        outer.addWidget(title)

        intro = QtWidgets.QLabel(
            "Send a Wi-Fi network name (SSID) and password to an ESP32 board "
            "plugged into this computer over USB. The values are sent only "
            "to the selected serial device. Nothing is uploaded to the "
            "internet."
        )
        intro.setWordWrap(True)
        outer.addWidget(intro)

        # -- Wi-Fi credentials group --------------------------------------- #
        wifi_group = QtWidgets.QGroupBox("Wi-Fi network")
        wifi_group.setAccessibleDescription(
            "Group of fields describing the Wi-Fi network to join."
        )
        wifi_form = QtWidgets.QFormLayout(wifi_group)
        wifi_form.setLabelAlignment(Qt.AlignmentFlag.AlignLeft)

        self.ssid_edit = QtWidgets.QComboBox()
        self.ssid_edit.setEditable(True)
        self.ssid_edit.setInsertPolicy(QtWidgets.QComboBox.InsertPolicy.NoInsert)
        self.ssid_edit.setDuplicatesEnabled(False)
        # Keep the UI bounded; start_provision validates the UTF-8 byte length.
        self.ssid_edit.lineEdit().setMaxLength(256)
        self.ssid_edit.setAccessibleName("SSID")
        self.ssid_edit.setAccessibleDescription(
            "Choose a detected Wi-Fi network name, or type an SSID that is not "
            "listed. Maximum 32 UTF-8 bytes."
        )
        self.ssid_edit.lineEdit().setPlaceholderText("Choose or type a network name")
        ssid_label = QtWidgets.QLabel("&SSID (network name):")
        ssid_label.setBuddy(self.ssid_edit)
        wifi_form.addRow(ssid_label, self.ssid_edit)

        self.pass_edit = QtWidgets.QLineEdit()
        self.pass_edit.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)
        self.pass_edit.setMaxLength(512)
        self.pass_edit.setAccessibleName("Password")
        self.pass_edit.setAccessibleDescription(
            "The Wi-Fi password. Leave blank only if the network is open. "
            "Maximum 63 UTF-8 bytes."
        )
        pass_label = QtWidgets.QLabel("&Password:")
        pass_label.setBuddy(self.pass_edit)
        wifi_form.addRow(pass_label, self.pass_edit)

        self.show_pass = QtWidgets.QCheckBox("S&how password")
        self.show_pass.setAccessibleDescription(
            "When checked, the Wi-Fi password is displayed as plain text "
            "instead of dots. Useful for verifying typing."
        )
        self.show_pass.toggled.connect(self._on_show_password_toggled)
        wifi_form.addRow(QtWidgets.QLabel(""), self.show_pass)

        outer.addWidget(wifi_group)

        # -- Serial port group --------------------------------------------- #
        port_group = QtWidgets.QGroupBox("Serial device")
        port_layout = QtWidgets.QHBoxLayout(port_group)

        self.port_combo = QtWidgets.QComboBox()
        self.port_combo.setAccessibleName("Serial port")
        self.port_combo.setAccessibleDescription(
            "Select the serial port that the ESP32 board is connected to. "
            "Use the Refresh button to re-scan the system after plugging "
            "in a board."
        )
        port_label = QtWidgets.QLabel("Por&t:")
        port_label.setBuddy(self.port_combo)

        self.refresh_btn = QtWidgets.QPushButton("&Refresh")
        self.refresh_btn.setAccessibleDescription(
            "Re-scan the system for connected serial ports."
        )
        self.refresh_btn.clicked.connect(self.refresh_ports)

        port_layout.addWidget(port_label)
        port_layout.addWidget(self.port_combo, 1)
        port_layout.addWidget(self.refresh_btn)
        outer.addWidget(port_group)

        # -- Action buttons ------------------------------------------------- #
        action_row = QtWidgets.QHBoxLayout()
        self.send_btn = QtWidgets.QPushButton("Sen&d to ESP32")
        self.send_btn.setDefault(True)
        self.send_btn.setAutoDefault(True)
        self.send_btn.setAccessibleDescription(
            "Send the entered Wi-Fi credentials to the selected ESP32 board."
        )
        self.send_btn.clicked.connect(self.start_provision)

        self.cancel_btn = QtWidgets.QPushButton("&Cancel")
        self.cancel_btn.setEnabled(False)
        self.cancel_btn.setAccessibleDescription(
            "Cancel the provisioning operation that is currently in progress."
        )
        self.cancel_btn.clicked.connect(self.cancel_provision)

        action_row.addWidget(self.send_btn)
        action_row.addWidget(self.cancel_btn)
        action_row.addStretch(1)
        outer.addLayout(action_row)

        # Allow Enter in either text field to start provisioning, mirroring
        # the web page's form-submit behaviour.
        self.ssid_edit.lineEdit().returnPressed.connect(self.start_provision)
        self.pass_edit.returnPressed.connect(self.start_provision)

        # -- Status (read-only line edit so it lives in the tab order) ----- #
        status_label = QtWidgets.QLabel("Status:")
        self.status_edit = QtWidgets.QLineEdit()
        self.status_edit.setReadOnly(True)
        self.status_edit.setAccessibleName("Status")
        self.status_edit.setAccessibleDescription(
            "Latest status of the provisioning operation. Read-only; "
            "tab here to read or copy the current status."
        )
        self.status_edit.setText(
            "Ready. Fill in the Wi-Fi details above and select Send to ESP32."
        )
        status_label.setBuddy(self.status_edit)
        outer.addWidget(status_label)
        outer.addWidget(self.status_edit)

        # -- Connected device name ----------------------------------------- #
        device_label = QtWidgets.QLabel("Connected device:")
        self.device_edit = QtWidgets.QLineEdit()
        self.device_edit.setReadOnly(True)
        self.device_edit.setPlaceholderText("(not connected)")
        self.device_edit.setAccessibleName("Connected device name")
        self.device_edit.setAccessibleDescription(
            "Human-readable device name advertised by the ESP32, when "
            "available. Read-only; tab here to read or copy the name."
        )
        device_label.setBuddy(self.device_edit)
        outer.addWidget(device_label)
        outer.addWidget(self.device_edit)

        # -- Serial log (read-only multi-line) ----------------------------- #
        log_label = QtWidgets.QLabel("Serial log:")
        self.log_edit = QtWidgets.QPlainTextEdit()
        self.log_edit.setReadOnly(True)
        self.log_edit.setLineWrapMode(QtWidgets.QPlainTextEdit.LineWrapMode.WidgetWidth)
        self.log_edit.setAccessibleName("Serial log")
        self.log_edit.setAccessibleDescription(
            "Raw serial traffic between this application and the ESP32. "
            "Lines starting with [TX] were sent by this computer; lines "
            "starting with [RX] were received from the ESP32. Read-only."
        )
        # Monospace font helps sighted users; harmless for AT users.
        mono = QtGui.QFontDatabase.systemFont(QtGui.QFontDatabase.SystemFont.FixedFont)
        self.log_edit.setFont(mono)
        log_label.setBuddy(self.log_edit)
        outer.addWidget(log_label)
        outer.addWidget(self.log_edit, 1)

        self.clear_log_btn = QtWidgets.QPushButton("Clear &log")
        self.clear_log_btn.setAccessibleDescription(
            "Clear the serial log display. Does not affect the ESP32."
        )
        self.clear_log_btn.clicked.connect(self._clear_log)
        outer.addWidget(self.clear_log_btn, 0, Qt.AlignmentFlag.AlignLeft)

        # -- Explicit tab order -------------------------------------------- #
        order = [
            self.ssid_edit,
            self.pass_edit,
            self.show_pass,
            self.port_combo,
            self.refresh_btn,
            self.send_btn,
            self.cancel_btn,
            self.status_edit,
            self.device_edit,
            self.log_edit,
            self.clear_log_btn,
        ]
        for first, second in zip(order, order[1:]):
            QtWidgets.QWidget.setTabOrder(first, second)

        self.ssid_edit.setFocus()

    # -- Slots / event handlers ------------------------------------------------
    def _on_show_password_toggled(self, checked: bool) -> None:
        """Toggle the password field between hidden and plain text."""
        mode = (
            QtWidgets.QLineEdit.EchoMode.Normal
            if checked
            else QtWidgets.QLineEdit.EchoMode.Password
        )
        self.pass_edit.setEchoMode(mode)

    def refresh_ssids(self) -> None:
        """Populate the SSID combobox with visible networks, preserving typing."""
        previous = self.ssid_edit.currentText()
        self.ssid_edit.clear()
        for ssid in list_wifi_ssids():
            self.ssid_edit.addItem(ssid)
        self.ssid_edit.setCurrentText(previous)

    def refresh_ports(self) -> None:
        """Repopulate the port combobox from the OS, preserving the selection."""
        previous = self.port_combo.currentData()
        self.port_combo.clear()
        for info in list_serial_ports():
            self.port_combo.addItem(info.label, info.device)
        if self.port_combo.count() == 0:
            self.port_combo.addItem("(no serial ports detected)", None)
        if previous is not None:
            idx = self.port_combo.findData(previous)
            if idx >= 0:
                self.port_combo.setCurrentIndex(idx)

    def start_provision(self) -> None:
        """Validate inputs and launch the worker thread.

        Called by the Send button and by Enter in either text field.
        Re-entrant calls while a worker is running are silently ignored.
        """
        if self._worker is not None and self._worker.isRunning():
            return

        ssid = self.ssid_edit.currentText().strip()
        # Passwords may legitimately contain leading/trailing spaces, so
        # do not strip the password value.
        password = self.pass_edit.text()

        if not ssid:
            self._set_status("Please enter the Wi-Fi network name (SSID).")
            self.ssid_edit.setFocus()
            return
        if len(ssid.encode("utf-8")) > SSID_MAX_BYTES:
            self._set_status(
                f"The SSID must be {SSID_MAX_BYTES} UTF-8 bytes or fewer."
            )
            self.ssid_edit.setFocus()
            return
        if len(password.encode("utf-8")) > PASS_MAX_BYTES:
            self._set_status(
                f"The password must be {PASS_MAX_BYTES} UTF-8 bytes or fewer."
            )
            self.pass_edit.setFocus()
            return

        port = self.port_combo.currentData()
        if not port:
            self._set_status(
                "Please select a serial port. Use Refresh if your board does "
                "not appear."
            )
            self.port_combo.setFocus()
            return

        self.device_edit.clear()
        self._set_status(f"Opening serial port {port} ...")
        self.send_btn.setEnabled(False)
        self.cancel_btn.setEnabled(True)

        worker = ProvisionWorker(port, ssid, password)
        worker.statusChanged.connect(self._set_status)
        worker.deviceName.connect(self._set_device_name)
        worker.logLine.connect(self._append_log)
        worker.failed.connect(self._on_failed)
        worker.succeeded.connect(self._on_succeeded)
        worker.finished.connect(self._on_worker_finished)
        self._worker = worker
        worker.start()

    def cancel_provision(self) -> None:
        """Ask the worker to stop. The worker emits a terminal signal."""
        if self._worker is not None and self._worker.isRunning():
            self.cancel_btn.setEnabled(False)
            self._set_status("Cancelling ...")
            self._worker.cancel()

    # -- UI updates ------------------------------------------------------------
    def _set_status(self, text: str) -> None:
        """Update the status field and announce the change to assistive tech."""
        self.status_edit.setText(text)
        self.status_edit.setCursorPosition(0)
        self._announce(self.status_edit)

    def _set_device_name(self, name: str) -> None:
        """Display the connected device name and announce it."""
        self.device_edit.setText(f"Connected to {name}")
        self.device_edit.setCursorPosition(0)
        self._announce(self.device_edit)

    @staticmethod
    def _announce(widget: QtWidgets.QWidget) -> None:
        """Fire a Qt accessibility ``Alert`` event so JAWS announces the value.

        On Windows this is mapped through the IAccessible2 / UIA bridge to
        a notification that JAWS reads aloud even when focus is elsewhere,
        which is the desktop equivalent of an ``aria-live`` region.
        """
        event = QtGui.QAccessibleEvent(widget, QtGui.QAccessible.Event.Alert)
        QtGui.QAccessible.updateAccessibility(event)

    def _append_log(self, direction: str, text: str) -> None:
        """Append a chunk of TX/RX traffic, prefixing each line with its tag."""
        if not text:
            return
        tag = f"[{direction}] "
        out_chars: list[str] = []
        for ch in text:
            if self._log_at_line_start:
                out_chars.append(tag)
                self._log_at_line_start = False
            out_chars.append(ch)
            if ch == "\n":
                self._log_at_line_start = True
        cursor = self.log_edit.textCursor()
        cursor.movePosition(QtGui.QTextCursor.MoveOperation.End)
        cursor.insertText("".join(out_chars))
        # Auto-scroll so new traffic is visible without disturbing the
        # caret position for users who tabbed into the log to read it.
        sb = self.log_edit.verticalScrollBar()
        sb.setValue(sb.maximum())

    def _clear_log(self) -> None:
        """Clear the on-screen serial log and reset the line-prefix tracker."""
        self.log_edit.clear()
        self._log_at_line_start = True

    def _on_failed(self, message: str) -> None:
        """Worker reported a terminal failure."""
        self._set_status(f"Error: {message}")

    def _on_succeeded(self) -> None:
        """Worker reported a terminal success."""
        # The final status message has already been emitted by the worker;
        # this slot exists for symmetry and future hooks.
        pass

    def _on_worker_finished(self) -> None:
        """QThread.finished — re-enable Send and clean up."""
        self.send_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        self._worker = None
        # Return focus to the Send button so a screen-reader user knows
        # the operation has completed and they can repeat it easily.
        self.send_btn.setFocus()

    # -- Lifecycle -------------------------------------------------------------
    def closeEvent(self, event: QtGui.QCloseEvent) -> None:  # noqa: N802 — Qt API
        """Cancel any in-flight worker and wait briefly before closing."""
        worker = self._worker
        if worker is not None and worker.isRunning():
            worker.cancel()
            worker.wait(2000)
        super().closeEvent(event)


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #

def main() -> int:
    """Application entry point. Returns the Qt exit code."""
    app = QtWidgets.QApplication(sys.argv)
    app.setApplicationName("ESP32 Wi-Fi Provisioner")
    app.setApplicationDisplayName("ESP32 Wi-Fi Provisioner")
    # Best-effort: enable Qt's built-in accessibility bridge. This is the
    # default on Windows but setting it explicitly is harmless and makes
    # the intent obvious.
    QtGui.QAccessible.setActive(True)

    apply_color_scheme(app)
    style_hints = app.styleHints()
    if hasattr(style_hints, "colorSchemeChanged"):
        style_hints.colorSchemeChanged.connect(lambda _scheme: apply_color_scheme(app))

    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
