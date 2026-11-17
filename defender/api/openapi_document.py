"""Write the API's OpenAPI document to `defender/api/openapi.json`, the file the frontend's build generates its types
from (#1540 F3). Run `python -m defender.api.openapi_document` after any API change that alters a shape; a test fails
while the committed file differs from what the app produces.

The app is built over placeholder dependencies: the document is a property of the routes, not of any database."""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path
from typing import Any

from defender._log import configure_from_env
from defender.api.app import create_app
from defender.api.ports import ApiDeps

DOCUMENT = Path(__file__).resolve().parent / "openapi.json"


def produce() -> dict[str, Any]:
    """The document `create_app` produces over a placeholder for every dependency."""
    deps: dict[str, Any] = {field.name: object() for field in dataclasses.fields(ApiDeps)}
    deps["frontend_origin"] = "http://localhost:1"
    return create_app(ApiDeps(**deps)).openapi()


def main() -> None:
    DOCUMENT.write_text(json.dumps(produce(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {DOCUMENT}")


if __name__ == "__main__":
    configure_from_env()
    main()
