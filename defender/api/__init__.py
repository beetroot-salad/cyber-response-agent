"""The platform HTTP API (#1131): the public endpoints the web app and integrations call.

A stub today. The routes, wire models, login seam and audit calls are the contract; the
records behind them come from in-memory fakes (`fakes.py`) until the store (#1082) and the
job model (#1081) land and implement the same ports (`ports.py`).

The API is its own program: it never imports the investigation runtime or the learning loop,
and never runs an investigation (`tests/test_api_stub.py` pins the import boundary).
"""
