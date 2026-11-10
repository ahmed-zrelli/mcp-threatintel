"""Windows toast notifications (no extra package), with a console fallback elsewhere.

The text comes from scan data (process names, file names), so it is never
interpolated into a script: it is XML-escaped, base64-encoded, and the fixed
PowerShell script only decodes it.
"""

from __future__ import annotations

import base64
import subprocess
import sys
from xml.sax.saxutils import escape

# AppUserModelID of Windows PowerShell: lets an unpackaged script show toasts.
_APP_ID = r"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe"

_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null
$xml = New-Object Windows.Data.Xml.Dom.XmlDocument
$xml.LoadXml([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__XML__')))
$toast = New-Object Windows.UI.Notifications.ToastNotification $xml
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('__APPID__').Show($toast)
"""


def toast_xml(title: str, lines: list[str]) -> str:
    texts = "".join(f"<text>{escape(t[:200])}</text>" for t in [title, *lines][:3])
    return (
        "<toast scenario='reminder'><visual><binding template='ToastGeneric'>"
        f"{texts}</binding></visual>"
        "<actions><action content='OK' arguments='dismiss' activationType='system'/></actions>"
        "<audio src='ms-winsoundevent:Notification.Looping.Alarm2'/></toast>"
    )


def notify(title: str, lines: list[str]) -> bool:
    """Show a toast on Windows. Returns False if it could not be shown."""
    if sys.platform != "win32":
        return False
    xml_b64 = base64.b64encode(toast_xml(title, lines).encode("utf-8")).decode("ascii")
    script = _SCRIPT.replace("__XML__", xml_b64).replace("__APPID__", _APP_ID)
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-EncodedCommand", encoded],
            capture_output=True, timeout=20,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),  # no console flash when run hidden
        )
        return proc.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False
