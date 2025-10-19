# tests/test_utils.py

import re

from utils import _replace_tag_sed

def test_replace_tag_sed_ce():
    out = _replace_tag_sed("docker-compose.yml", "18.4.1", "ce")
    assert out == (
        "sed -i -E 's|gitlab/gitlab-ce:[0-9]+\\.[0-9]+\\.[0-9]+-ce\\.0|"
        "gitlab/gitlab-ce:18.4.1-ce.0|' docker-compose.yml"
    )
    m = re.search(r"gitlab/gitlab-ce:([0-9]+\.[0-9]+\.[0-9]+)-ce\.0", out)
    assert m


def test_replace_tag_sed_ee():
    out = _replace_tag_sed("prod-compose.yml", "17.11.0", "ee")
    assert out == (
        "sed -i -E 's|gitlab/gitlab-ee:[0-9]+\\.[0-9]+\\.[0-9]+-ee\\.0|"
        "gitlab/gitlab-ee:17.11.0-ee.0|' prod-compose.yml"
    )


def test_replace_tag_sed_different_file():
    out = _replace_tag_sed("custom.yml", "15.0.0", "ce")
    assert out.endswith(" custom.yml")
