# Advanced-Multi-Secret-Scanner-Finder

An advanced, hacker-themed GUI tool that sweeps codebases for potential secrets such as API keys, credentials, certificates, and private keys.

## Features

- 🔍 Multi-pattern and heuristic scanning for well-known cloud tokens, JWTs, SSH keys, service accounts, webhook secrets, and entropy-based anomalies
- ⚙️ Configurable scan options including hidden-file traversal, entropy heuristics, max file size, extension allow lists, and thread pool sizing
- ⚡️ Parallelized engine with async wrappers for single scans and multi-directory batch sweeps
- 📂 Highlights sensitive filenames, extensions, and directories (e.g., `.pem`, `.kdbx`, `.ssh`, `service-account.json`)
- 📊 Interactive results notebook with severity filters, live search, context previews, and clipboard export
- 🧠 Intelligence tab summarizing suspicious assets for quick triage and reporting
- 🗂 Batch operations queue with concurrent workers, live progress, and job-level summaries
- 💾 Export findings to JSON and intelligence snapshots to text for downstream tooling
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
   - Click **Browse** to select the directory you want to audit or queue multiple targets on the **Batch Ops** tab.
   - Tweak scan options (hidden files, entropy heuristics, thread count, extension filters) in the **Scan Options** panel.
   - Hit **Initiate Scan** to launch a multithreaded sweep with live progress, timer, and stats.
   - Slice and dice findings by severity or search keywords, inspect full context, and export JSON or metadata reports.
   - Schedule concurrent batch jobs to triage several repositories simultaneously.

> ⚠️  The scanner focuses on textual files and ignores binaries and very large files by default. Adjust limits and extend detection rules by editing the modules in `secret_scanner_gui/`.

## Development Notes

- The scanning logic lives in `secret_scanner_gui/scanner.py`.
- Predefined detection patterns are centralized in `secret_scanner_gui/scan_patterns.py` for easy customization.
- The Tkinter interface and styling are defined in `secret_scanner_gui/gui.py`.

Contributions and additional secret signatures are welcome!
