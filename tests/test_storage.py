import pytest

from common.record import FileRecord, new_file_id
from server.storage import HonestServer


def _record(name="a.txt") -> FileRecord:
    return FileRecord(
        file_id=new_file_id(),
        name=name,
        wrapped_key=b"\x00" * 48,
        nonce_or_iv=b"\x01" * 16,
        ciphertext=b"\x02" * 32,
        version=1,
    )


def test_put_get_roundtrip(server):
    rec = _record()
    server.put(rec.to_dict())
    assert FileRecord.from_dict(server.get(rec.file_id)) == rec


def test_list_returns_all(server):
    recs = [_record(f"{i}.txt") for i in range(3)]
    for r in recs:
        server.put(r.to_dict())
    assert {d["file_id"] for d in server.list()} == {r.file_id for r in recs}


def test_put_overwrites(server):
    rec = _record()
    server.put(rec.to_dict())
    rec.name = "renamed.txt"
    server.put(rec.to_dict())
    assert server.get(rec.file_id)["name"] == "renamed.txt"
    assert len(server.list()) == 1


def test_get_missing_raises(server):
    with pytest.raises(KeyError):
        server.get(new_file_id())


def test_persists_across_instances(tmp_path):
    rec = _record()
    HonestServer(tmp_path).put(rec.to_dict())
    assert HonestServer(tmp_path).get(rec.file_id) == rec.to_dict()


def test_meta(server):
    assert server.get_meta("salt") is None
    server.put_meta("salt", {"salt": "abc"})
    assert server.get_meta("salt") == {"salt": "abc"}


@pytest.mark.parametrize("bad", ["../evil", "a/b", "", "x" * 65])
def test_rejects_unsafe_ids(server, bad):
    with pytest.raises(ValueError):
        server.get(bad)
