import json
from pathlib import Path


def load_shodan_fixture() -> dict:
    """
    Load the saved Shodan API response fixture.
    Returns a dict matching the structure of shodan.Shodan().search() output:
    {'matches': [...], 'total': N}

    The fixture file is NDJSON (one JSON object per line).  Only the first
    record is used so that the returned structure always contains exactly
    one result with known, stable field values suitable for assertions.
    """
    path = Path(__file__).parent / 'fixtures' / 'shodan_response.json'
    first_line = path.read_text().splitlines()[0]
    record = json.loads(first_line)
    return {'matches': [record], 'total': 1}
