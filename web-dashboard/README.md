# Frida Network Dashboard

Optional browser UI for the Android TCP Sniffer. It attaches to an already-running Android application through a Frida TCP endpoint and displays read-only TCP/UDP socket API telemetry.

## Features

- Running application picker and attach/detach controls
- Live TCP and UDP send/receive event table
- Remote endpoint, byte count, timestamp and payload preview
- Hex and ASCII detail view
- Protocol/direction filters and endpoint/payload search
- Event counters, pause/resume, clear and JSON export
- Random password protection when bound to a LAN interface

## Requirements

- Python 3.10 or newer
- The repository's Python requirements installed (\`frida-tools\` provides the Python Frida binding)
- Android \`frida-server\` running and reachable from the Pi
- Frida Python client and \`frida-server\` versions matching

## Wireless ADB setup

Pair and connect Android Wireless debugging as described in the root [Wireless ADB guide](../README.md#-wireless-adb-raspberry-pi--wi-fi). Then forward Frida's device port to the Pi's loopback interface:

\`\`\`bash
adb devices -l
adb -s <phone-ip>:<wireless-port> forward tcp:27042 tcp:27042
frida-ps -H 127.0.0.1:27042 -ai
\`\`\`

The final command should list the phone's applications before starting the dashboard.

## Start the dashboard

From the repository root:

\`\`\`bash
python3 web-dashboard/server.py \\
  --remote 127.0.0.1:27042 \\
  --host 0.0.0.0 \\
  --port 8765
\`\`\`

The server prints a generated LAN password. Open \`http://PI_LAN_IP:8765\` on a browser and sign in with username \`frida\` and that password.

For local-only access on the Raspberry Pi, omit \`--host 0.0.0.0\` and open \`http://127.0.0.1:8765\`.

## Use

1. Start the target app normally on Android.
2. Open the dashboard and press **Refresh apps**.
3. Select the running app and press **Attach**.
4. Generate network activity in the app. Events appear in the table.
5. Select an event to inspect ASCII and hex data; use **Export JSON** to save events.
6. Press **Detach** when finished.

## Scope and limitations

This dashboard observes socket API buffers through \`socket\`, \`connect\`, \`send\`, \`recv\`, \`sendto\`, \`recvfrom\`, \`read\` and \`write\` hooks. It is socket-level telemetry, not a packet capture, so it does not reconstruct TCP segments, retransmissions or PCAP files. TLS/HTTPS payloads and QUIC application data generally remain encrypted at this layer. The existing CLI analyzer remains the project's option for its separate SSL hooks and PCAP/HAR/Burp exports.

The dashboard is attach-only; it never spawns or restarts the target process. Hooking adds overhead and some applications use alternate networking APIs that are not covered.

**Security:** The dashboard controls a Frida session and can inspect application memory. Keep it on a trusted LAN, retain the generated password, and do not expose port 8765 directly to the public internet. Use it only on applications and devices you own or are authorized to test.
