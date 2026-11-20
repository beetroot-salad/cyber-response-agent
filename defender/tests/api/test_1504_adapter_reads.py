"""#1504: `PUT /systems/<id>` refuses a record whose non-GET reads are not its adapter's, naming the missing route
(O3 at the store). Names left open by the design: `_reads1504`."""
from __future__ import annotations

import pytest

from defender.tests.support.api._config1470 import ELASTIC, ELASTIC_SETTINGS
from defender.tests.support.tenancy import _systems1366 as R
from defender.tests.systems import _reads1504 as X

pytestmark = [pytest.mark.anyio, pytest.mark.postgres]


async def test_1504_o2_the_store_refuses_a_system_whose_reads_miss_one_of_its_adapters_naming_it(scripted):
    """`PUT /systems/elastic` with only the search read is 422, a fault naming the missing `POST /_query`. (O3)"""
    access = R.declaration("https://elasticsearch.example:9200", scheme="basic", reads=X.ELASTIC_READS[:1])
    refused = await scripted.put_system(ELASTIC, 0, settings=ELASTIC_SETTINGS, access=access)
    assert refused.status_code == 422, refused.text
    assert [f for f in refused.json()["faults"] if X.shown(X.ELASTIC_READS[1]) in f], refused.json()
