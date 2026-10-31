name: Python Tests

on:
  push:
    branches: [ "main" ]
  pull_request:
    branches: [ "main" ]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ["3.10", "3.11", "3.12"]

    steps:
      - uses: actions/checkout@v4

      - name: Set up Python ${{ matrix.python-version }}
        uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}

      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -r requirements.txt

      - name: Run test suite
        run: |
          pytest tests/ -v

      - name: Smoke-test CLI (non-interactive)
        run: |
          mkdir -p lab/original
          echo "CI smoke test file" > lab/original/ci_sample.txt
          python -m src.main protect --file lab/original/ci_sample.txt --password "CiTestPassphrase!2026"
          python -m src.main integrity --file lab/original/ci_sample.txt
          python -m src.main decrypt --file lab/protected/ci_sample.fslb --password "CiTestPassphrase!2026"
          python -m src.main report --file lab/original/ci_sample.txt
          python -m src.main vuln-demo
