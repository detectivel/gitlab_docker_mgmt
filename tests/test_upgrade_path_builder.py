# tests/test_upgrade_path_builder.py

from __future__ import annotations

from gitlab_projects import (
    _build_ladder,
    _extract_official_path,
)


def test_build_ladder_prefers_minor_within_window():
    versions = [
        "15.11.2",
        "16.0.10",
        "16.1.5",
        "16.2.9",
        "16.3.4",
        "16.4.3",
    ]

    ladder = _build_ladder(versions, "16.0.10")

    # should move within the +2 minor window (0 -> 2 -> 4)
    assert ladder == ["16.2.9", "16.4.3"]


def test_build_ladder_falls_back_to_last_minor_when_sparse():
    versions = [
        "15.11.2",
        "16.3.9",
        "16.11.10",
        "17.8.5",
        "18.4.2",
    ]

    ladder = _build_ladder(versions, "15.11.2")

    # without the fallback this would jump straight to 17.8.5
    assert ladder == ["16.3.9", "16.11.10", "17.8.5", "18.4.2"]


def test_extract_official_path_from_nested_structure():
    metadata = {
        "path": {
            "docker": {
                "ee": {
                    "15.11.13": [
                        "15.11.13-ee.0",  # should be ignored
                        "16.3.9-ee.0",
                        "16.4.1-ee.0",
                        "16.7.8-ee.0",
                        "16.11.10-ee.0",
                    ]
                }
            }
        }
    }

    ladder = _extract_official_path(metadata, "15.11.13")

    assert ladder == ["16.3.9", "16.4.1", "16.7.8", "16.11.10"]


def test_extract_official_path_handles_object_entries():
    metadata = {
        "path": [
            {
                "from": "16.3.9-ee.0",
                "path": [
                    "16.3.9-ee.0",  # dedupe current
                    "16.4.1-ee.0",
                    "16.7.8-ee.0",
                ],
            }
        ]
    }

    ladder = _extract_official_path(metadata, "16.3.9")

    assert ladder == ["16.4.1", "16.7.8"]
