import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.schemas.dependency import DependencyDocument, DependencyRelationship
from app.schemas.graph import GraphDocument
from app.schemas.inventory import Inventory
from app.schemas.scan import ScanState

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.mark.parametrize(
    ("filename", "model_type"),
    [
        ("inventory.json", Inventory),
        ("normalized.json", DependencyDocument),
        ("graph.json", GraphDocument),
        ("scan.json", ScanState),
    ],
)
def test_readme_contract_fixtures_validate(filename: str, model_type: type) -> None:
    payload = json.loads((FIXTURES / filename).read_text(encoding="utf-8"))
    validated = model_type.model_validate(payload)
    assert model_type.model_validate(validated.model_dump(mode="json")) == validated


def test_contracts_reject_unknown_fields() -> None:
    payload = json.loads((FIXTURES / "inventory.json").read_text(encoding="utf-8"))
    payload["invented_field"] = "must not drift"
    with pytest.raises(ValidationError):
        Inventory.model_validate(payload)


def test_unresolved_relationship_requires_target_and_null_to_id() -> None:
    relationship = DependencyRelationship.model_validate(
        {
            "relationship_id": "rel:unknown",
            "from_id": "root:demo",
            "to_id": None,
            "unresolved_target": {
                "name": "requests",
                "specifier": ">=2,<3",
                "ecosystem": "pypi",
            },
            "resolution_status": "unresolved",
            "type": "DEPENDS_ON",
            "evidence": [
                {"path": "requirements.txt", "kind": "manifest", "locator": "line:1"}
            ],
        }
    )
    assert relationship.to_id is None

    invalid = relationship.model_dump()
    invalid["to_id"] = "cmp:guessed"
    with pytest.raises(ValidationError):
        DependencyRelationship.model_validate(invalid)

