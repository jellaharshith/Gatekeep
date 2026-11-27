# Notebooks

`phase2_colab.ipynb` runs the real-model baseline (Phase 2) on a Colab GPU: Ollama serves `qwen3:8b` and
`llama3.1:8b`, Gatekeep runs the benchmark in resumable chunks written to Google Drive, then merges them into one
`report.md` / `summary.json`.

Open in Colab: https://colab.research.google.com/github/jellaharshith/Gatekeep/blob/main/notebooks/phase2_colab.ipynb

Export only `summary.json` and `report.md` to `results/`. Do not commit raw transcripts. Numbers from `sim:*` models are not findings.
