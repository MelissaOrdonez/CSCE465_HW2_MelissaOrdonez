How to set up the environment:
Run commands `python3 -m venv .venv` and `source .venv/bin/activate` to set up a virtual environment. Install these packages if needed `python -m pip install --upgrade pip` and `python -m pip install cryptography==49.0.0 pytest==9.1.1`

To generate the group file needed to run handshake.py run the command `openssl genpkey -genparam -algorithm DH -pkeyopt group:ffdhe3072 -out ffdhe3072.pem`

How to run the files/tests:
Task 1: Run `python3 baseline_ctr.py`
Task 2: Run `python3 handshake.py`
Task 3: Tested with test_file.py not run independently
Task 4: Run `pytest -v`

