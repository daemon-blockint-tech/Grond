"""Unit tests for Exiv2 CLI stdout parsing (no exiv2 binary required)."""

from src.exiv2_pa_parse import parse_exiv2_print_a


def test_parse_exiv2_sample_lines() -> None:
    sample = """
Some noise line
Exif.Photo.Make                              Ascii      18  Canon
0x0004 set Nikon3       Exif.Nikon3.Quality   Ascii       8  NORMAL
Xmp.dc.subject                               XmpBag      1  Monument
"""
    tags = parse_exiv2_print_a(sample)
    assert tags["Exif.Photo.Make"] == "Canon"
    assert tags["Exif.Nikon3.Quality"] == "NORMAL"
    assert tags["Xmp.dc.subject"] == "Monument"


def test_parse_exiv2_empty() -> None:
    assert parse_exiv2_print_a("") == {}
