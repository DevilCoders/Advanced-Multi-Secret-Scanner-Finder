# Advanced-Multi-Secret-Scanner-Finder

An advanced, hacker-themed GUI tool that sweeps codebases for potential secrets such as API keys, credentials, certificates, and private keys.

## Features

- 🔍 Expanded signature set covering popular cloud APIs, Vault tokens, OAuth secrets, and entropy-based heuristics
- ⚙️ Configurable scan settings (hidden files, max file size, extension filters, worker counts, heuristics toggle)
- 🧵 Multi-threaded directory sweeps with async pipelines for responsive progress updates
- 📊 Interactive results explorer with severity filters, keyword search, and double-click to open files
- 🛰️ Batch operations tab for concurrently scanning multiple repositories with per-job summaries
- 🧠 Metadata insights that highlight sensitive filenames and extensions alongside heuristic hit counts
- 💾 Export findings to JSON for downstream processing or compliance tracking
- 🧑‍💻 Sleek neon-on-black “hacker” aesthetic powered by Tkinter styling

## Getting Started

1. **Install dependencies** (Python 3.10+ recommended):

   ```bash
   pip install -r requirements.txt
   ```

2. **Launch the GUI**:

   ```bash
   python app.py
   ```

3. **Use the interface**:
   - Select the **Single Scan** tab to target one repository, configure scan settings, and launch a deep search.
   - Apply keyword filters or severity toggles to focus on high-impact hits, then export or open files directly.
   - Switch to **Batch Operations** to queue multiple directories, set concurrency, and review summarized outcomes.

> ⚠️  The scanner focuses on textual files and ignores binaries and very large files by default. Adjust limits and extend detection rules by editing the modules in `secret_scanner_gui/`.

## Development Notes

- The scanning logic lives in `secret_scanner_gui/scanner.py`.
- Predefined detection patterns are centralized in `secret_scanner_gui/scan_patterns.py` for easy customization.
- The Tkinter interface and styling are defined in `secret_scanner_gui/gui.py`.

Contributions and additional secret signatures are welcome!
