import threading

import pytest

import material_bundle_stager as ms


def stager(**kw):
    return ms.MaterialBundleStager(**kw)


def member(name, kind="file", size=10, csize=5):
    return {"name": name, "kind": kind, "size": size, "csize": csize}


BUNDLE = [
    member("cover.png", size=100, csize=80),
    member("src/", kind="dir", size=0, csize=0),
    member("src/main.js", size=200, csize=90),
]


def test_plan_is_sorted_and_commit_reports_written_paths():
    s = stager()
    plan = s.plan(list(BUNDLE), target_root="/srv/materials")
    assert plan["paths"] == ["cover.png", "src/", "src/main.js"]
    assert plan["total_bytes"] == 300
    assert plan["root"] == "/srv/materials"
    out = s.commit(plan)
    assert out["written"] == ["cover.png", "src/", "src/main.js"]
    snap = s.snapshot()
    assert snap["planned"] == 1
    assert snap["committed"] == 1


def test_parent_segment_is_rejected():
    with pytest.raises(ms.StageError) as exc:
        stager().plan([member("../etc/passwd.txt")], target_root="/srv/m")
    assert exc.value.code == "parent_segment"


def test_absolute_path_is_rejected():
    with pytest.raises(ms.StageError) as exc:
        stager().plan([member("/etc/passwd.txt")], target_root="/srv/m")
    assert exc.value.code == "absolute_path"


def test_windows_drive_is_rejected():
    with pytest.raises(ms.StageError) as exc:
        stager().plan([member("C:/temp/a.txt")], target_root="/srv/m")
    assert exc.value.code == "drive_letter"


def test_backslash_is_rejected():
    with pytest.raises(ms.StageError) as exc:
        stager().plan([member("src\\main.js")], target_root="/srv/m")
    assert exc.value.code == "bad_separator"


def test_empty_segment_is_rejected():
    with pytest.raises(ms.StageError) as exc:
        stager().plan([member("src//main.js")], target_root="/srv/m")
    assert exc.value.code == "empty_segment"


def test_dot_segment_is_rejected():
    with pytest.raises(ms.StageError) as exc:
        stager().plan([member("./cover.png")], target_root="/srv/m")
    assert exc.value.code == "dot_segment"


def test_link_members_are_rejected():
    with pytest.raises(ms.StageError) as exc:
        stager().plan([member("shortcut", kind="symlink")], target_root="/srv/m")
    assert exc.value.code == "links_not_allowed"


def test_entry_budget_is_enforced():
    with pytest.raises(ms.StageError) as exc:
        stager(max_entries=2).plan(list(BUNDLE), target_root="/srv/m")
    assert exc.value.code == "too_many_entries"


def test_total_size_budget_is_enforced():
    with pytest.raises(ms.StageError) as exc:
        stager(max_total=250).plan(list(BUNDLE), target_root="/srv/m")
    assert exc.value.code == "total_too_large"


def test_single_entry_budget_is_enforced():
    with pytest.raises(ms.StageError) as exc:
        stager(max_entry=150).plan(list(BUNDLE), target_root="/srv/m")
    assert exc.value.code == "entry_too_large"


def test_case_collision_is_rejected():
    members = [member("Cover.png"), member("cover.png")]
    with pytest.raises(ms.StageError) as exc:
        stager().plan(members, target_root="/srv/m")
    assert exc.value.code == "duplicate_member"


def test_reserved_device_name_is_rejected():
    with pytest.raises(ms.StageError) as exc:
        stager().plan([member("con.txt")], target_root="/srv/m")
    assert exc.value.code == "reserved_name"


def test_file_and_directory_conflict_is_rejected():
    members = [member("notes"), member("notes/", kind="dir", size=0, csize=0)]
    with pytest.raises(ms.StageError) as exc:
        stager().plan(members, target_root="/srv/m")
    assert exc.value.code == "path_conflict"


def test_concurrent_plan_and_commit_are_counted():
    s = stager()
    problems = []

    def worker():
        try:
            plan = s.plan(list(BUNDLE), target_root="/srv/m")
            s.commit(plan)
        except Exception as exc:  # noqa: BLE001
            problems.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert problems == []
    snap = s.snapshot()
    assert snap["planned"] == 6
    assert snap["committed"] == 6
    snap["planned"] = 0
    assert s.snapshot()["planned"] == 6
