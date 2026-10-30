# Developer helpers (not shipped)

Used to test EVTXER for real - the GUI, Hayabusa upgrades, the dashboards -
beyond the unit tests. Never shipped with the tool.

| File | What it is for |
|---|---|
| `uia.ps1` | UI Automation helpers: find EVTXER's window (by title or process id), click buttons by x:Name or text, read labels, select tabs and list rows, find a dialog the window owns. |
| `winshot.ps1` | A picture of one EVTXER window, optionally resized and on a given tab. PrintWindow, never a screen region. |
| `run-some-tests.ps1` | Run named test files the way `tests\run-tests.ps1` does. |
| `hayabusa_scan_count.py` | Runs one Hayabusa scan and counts detections per rule while the results file is written (Defender locks results that quote attack commands once they are closed). For comparing two Hayabusa versions on `evtx-samples\`. |
| `fetch_sources.py` | `hayabusa 4.2.0` / `takajo 2.16.1`: puts that release's source (code only) into `code\licenses\`, as the AGPL requires when EVTXER passes the binaries on. Run on every Hayabusa/Takajo upgrade. |
| `make_icon.py` | Builds `code\assets\app.ico` (the Stoop mark, 16-256 px) and, given a second path, a preview sheet. |
| `scratch-evtxer.ps1` | `-Action New/Start/Stop/Status`: the scratch copy in `%TEMP%\evx`; `Stop` closes it and checks none is left. |
| `winrm_https_target.ps1` | Run ON a test target as administrator: `-Action Setup -AllowFrom <IP>` makes a temporary WinRM-over-HTTPS listener (self-signed, firewall open to that IP only, LocalAccountTokenFilterPolicy=1); `-Action Remove` restores exactly what it recorded. For the never-run live WinRM-HTTPS collection test. |
| `patch.py` | Exact replacements from a spec file, keeping CRLF/BOM; all or nothing. |
| `check_panels.py` | Does every Lens panel of an ndjson have data on an ES/index? Read-only; `--runtime-from` for op.* fields. |
| `hayabusa_compare.py` | Two Hayabusa builds on the same EVTX: detections, output fields, per-rule changes. |

GUI testing rules (learned the hard way):

- Drive a **scratch copy** of `code\` (one EVTXER per install - the lock is
  per `code\` folder), in a SHORT path such as `%TEMP%\evx` (the rules have
  166-character paths). Start it with `Start-Process -PassThru` so you know
  its process id, and **close it when the test ends** (WindowPattern.Close,
  then check the process is gone). Never leave EVTXER windows running.
- A modal dialog blocks the click that opened it: click from a `Start-Job`,
  then find the dialog under the main window (`Get-UiOwned`).
- A Win32 MessageBox exposes no buttons to UI Automation: answer it with
  `SendKeys '{ENTER}'` (Yes/OK is the default) - only while the screen is
  unlocked. The Save dialog's file-type list cannot be driven; a stray Enter
  in it SAVES into the last-used folder (once into the repo's output\).
- Windows Defender quarantines files and command lines that name attack
  tools (the Mimikatz sample's file name) - refer to such files by wildcard
  inside a script, never on a command line.
