# Advanced-Multi-Secret-Scanner-Finder

An advanced, hacker-themed GUI tool that sweeps codebases for potential secrets such as API keys, credentials, certificates, and private keys.

## Features

- 🔍 Extended pattern engine with entropy heuristics for modern API tokens (OpenAI, GitLab, DigitalOcean, Terraform Cloud, etc.)
- ⚡️ Async-enabled, multi-threaded scanning core with batch orchestration for large codebases
- 📂 Smart directory traversal with binary detection, file size limits, and extension filtering
- ⚠️ Highlights sensitive filenames/extensions and surfaces metadata intelligence dashboards
- 🧮 Real-time progress indicator, timer, severity filters, and contextual code previews
- 📊 Notebook-driven GUI with live results, batch management, and threat intel panels
- 💾 Export results to JSON for further analysis and sharing
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
   - Click **Browse** to select the directory you want to audit or queue multiple targets for batch scans.
   - Hit **Initiate Scan** for single-target reconnaissance or run **Batch Ops** to process many repositories in parallel.
   - Filter findings by severity/search, inspect contextual code snippets, review threat intel, and export when ready.

> ⚠️  The scanner focuses on textual files and ignores binaries and very large files by default. Adjust limits and extend detection rules by editing the modules in `secret_scanner_gui/`.

## Development Notes

- The scanning logic lives in `secret_scanner_gui/scanner.py`.
- Predefined detection patterns are centralized in `secret_scanner_gui/scan_patterns.py` for easy customization.
- The Tkinter interface and styling are defined in `secret_scanner_gui/gui.py`.

Contributions and additional secret signatures are welcome!
