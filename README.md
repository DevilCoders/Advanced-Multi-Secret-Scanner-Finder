# Advanced-Multi-Secret-Scanner-Finder

An advanced, hacker-themed GUI tool that sweeps codebases for potential secrets such as API keys, credentials, certificates, and private keys.

## Features

- 🔍 Extended signature library covering cloud tokens, OAuth secrets, API keys, Docker auth, Terraform state secrets, and more
- 📂 Concurrent directory traversal with binary file detection, adjustable size limits, and optional entropy analysis
- ⚙️ Configurable worker threads, extension allow-lists, and hidden-file scanning toggles
- 🧮 Real-time progress indicator, asynchronous execution, timer, and severity/entropy summary
- 📊 Interactive findings notebook with severity filters, search, detail inspector, and metadata dashboards
- 🗃️ Batch queue manager for back-to-back repository scans with consolidated status updates
- 💾 Export results to JSON for further analysis
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
   - Click **Browse** to select the directory you want to audit.
   - Adjust worker threads, entropy detection, hidden file inclusion, and extension filters from the **Scan Controls** panel.
   - Hit **Initiate Scan** and watch the asynchronous progress bar as the tool inspects every readable file.
   - Filter findings by severity, search keywords, inspect detailed metadata, and export results on demand.
   - Queue multiple directories with **Add to Batch** and process them back-to-back using **Run Batch**.

> ⚠️  The scanner focuses on textual files and ignores binaries and very large files by default. Adjust limits and extend detection rules by editing the modules in `secret_scanner_gui/`.

## Development Notes

- The scanning logic lives in `secret_scanner_gui/scanner.py`.
- Predefined detection patterns are centralized in `secret_scanner_gui/scan_patterns.py` for easy customization.
- The Tkinter interface and styling are defined in `secret_scanner_gui/gui.py`.

Contributions and additional secret signatures are welcome!
