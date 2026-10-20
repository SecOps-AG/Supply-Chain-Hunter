from hunter.jev import newer_than_pin


def test_newer_catalog_ids_ignore_aliases():
    assert newer_than_pin(["jev-latest", "jev-1.13.0", "jev-preview"], "jev-1.13.0") == []
    assert newer_than_pin(["jev-1.14.0"], "jev-1.13.0") == ["jev-1.14.0"]
