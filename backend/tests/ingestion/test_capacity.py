from app.ingestion.capacity import ScanCapacity


def test_capacity_reserves_and_releases_slots() -> None:
    capacity = ScanCapacity(1)
    assert capacity.reserve() is True
    assert capacity.active == 1
    assert capacity.reserve() is False
    capacity.release()
    assert capacity.active == 0
    assert capacity.reserve() is True

