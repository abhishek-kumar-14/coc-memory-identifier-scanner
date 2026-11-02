# COC Memory Identifier Scanner

A lightweight C-based memory analysis utility designed for Clash of Clans running on Android/Linux environments.

The program scans selected process memory regions for SCID-formatted and GCID identifier patterns and attempts to overwrite detected memory locations with zero bytes.

## Features

- **Process Detection:** Automatically searches for the Clash of Clans process.
- **SCID Detection:** Identifies SCID-formatted hexadecimal identifiers.
- **GCID Detection:** Searches for numeric GCID patterns beginning with `G:`.
- **Memory Scanning:** Reads selected memory regions through the Linux `/proc` filesystem.
- **Memory Operations:** Attempts to overwrite detected identifier locations with zero bytes.
- **Custom Process Support:** Allows specifying a target process name.
- **Result Logging:** Saves scanning results to a text file.

## Requirements

- Android device or compatible Linux environment.
- A compatible C compiler (GCC or Clang).
- Android Debug Bridge (ADB).
- Android NDK for Android builds.
- Appropriate process memory access permissions.

## Repository Structure

```text
coc-memory-identifier-scanner/
│
├── platform.c
└── README.md
```

## Compilation

Compile the source using GCC in a compatible Linux environment:

```bash
gcc -O2 -Wall -Wextra platform.c -o platform
```

For Android, compile using the Android NDK Clang toolchain targeting the device architecture.

## Installation & Usage

### 1. Compile the executable

Build `platform` using a compiler compatible with your target Android architecture.

### 2. Transfer the executable

Connect your Android device using ADB and execute:

```bash
adb push platform /data/local/tmp/platform
```

### 3. Set permissions

Grant the executable permissions:

```bash
adb shell chmod 777 /data/local/tmp/platform
```

### 4. Enter the device shell

```bash
adb shell
```

### 5. Navigate to the directory

```bash
cd /data/local/tmp
```

### 6. Execute the program

Run using the default process name:

```bash
./platform
```

Alternatively, specify a custom process name:

```bash
./platform clashofclans
```

**Note:** Use this utility only with accounts and processes you own or are explicitly authorized to test. Do not use it to extract another player's identifiers or modify another player's game session.

## Output

The program redirects its output to:

```text
/data/local/tmp/platform.txt
```

To view the results:

```bash
cat /data/local/tmp/platform.txt
```

### Result Format

| Output | Description |
|---|---|
| `Yes (G:...)` | GCID pattern detected and overwrite succeeded |
| `Flush Failed` | GCID detected but overwrite failed |
| `No` | GCID not detected or not successfully cleared |
| SCID value | Detected SCID-formatted identifier |
| `Not Found` | SCID pattern not detected |

## Technical Information

| Component | Implementation |
|---|---|
| Programming Language | C |
| Operating Environment | Android / Linux |
| Process Detection | `/proc` |
| Memory Mapping | `/proc/PID/maps` |
| Memory Reading | `/proc/PID/mem` |
| Memory Writing | `/proc/PID/mem` |
| Output | Text file |
| Output Directory | `/data/local/tmp/` |

## Important Notes

- Process memory access depends on Android/Linux security restrictions.
- Root access or additional permissions may be required.
- Results depend on the game's version and memory layout.
- Detected patterns are not guaranteed to represent valid account identifiers.
- Memory modification can cause application instability or crashes.
- The executable must match the target device architecture.

## Disclaimer

This is an unofficial independent research project. It is not affiliated with, endorsed by, or associated with Supercell.

Clash of Clans and Supercell are trademarks of Supercell.

This project is intended for educational purposes and authorized testing only. The author is not responsible for misuse, application instability, account issues, or any consequences resulting from unauthorized use.
