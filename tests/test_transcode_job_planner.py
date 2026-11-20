import pytest

import transcode_job_planner as tp

WORK = "/work"
FILTERS = {"scale", "fps", "pad"}


def planner(runner=None, **kw):
    return tp.TranscodeJobPlanner(WORK, FILTERS, runner=runner, **kw)


def job(**over):
    j = {
        "input_key": "in/clip.mov",
        "output_key": "out/clip.mp4",
        "preset": "fast",
        "filters": ["scale=640"],
        "crf": 23,
        "label": "promo",
    }
    j.update(over)
    return j


def test_plan_uses_fixed_argument_array():
    plan = planner().plan(job())
    assert plan["argv"] == [
        "ffmpeg",
        "-nostdin",
        "-y",
        "-i",
        "/work/in/clip.mov",
        "-vf",
        "scale=640",
        "-preset",
        "fast",
        "-crf",
        "23",
        "/work/out/clip.mp4",
    ]
    assert plan["output_path"] == "/work/out/clip.mp4"
    assert plan["display"] == "promo"


def test_parent_segment_in_input_key_is_rejected():
    with pytest.raises(tp.PlanError) as exc:
        planner().plan(job(input_key="../secret.mov"))
    assert exc.value.code == "parent_segment"


def test_absolute_output_key_is_rejected():
    with pytest.raises(tp.PlanError) as exc:
        planner().plan(job(output_key="/etc/out.mp4"))
    assert exc.value.code == "absolute_path"


def test_output_suffix_is_checked():
    with pytest.raises(tp.PlanError) as exc:
        planner().plan(job(output_key="out/clip.avi"))
    assert exc.value.code == "bad_suffix"


def test_filter_outside_allowlist_is_rejected():
    with pytest.raises(tp.PlanError) as exc:
        planner().plan(job(filters=["drawtext=1"]))
    assert exc.value.code == "filter_not_allowed"


def test_option_like_filter_is_rejected():
    with pytest.raises(tp.PlanError) as exc:
        planner().plan(job(filters=["-vf"]))
    assert exc.value.code == "filter_not_allowed"


def test_filter_parameter_format_is_checked():
    with pytest.raises(tp.PlanError) as exc:
        planner().plan(job(filters=["scale=abc"]))
    assert exc.value.code == "bad_filter"


def test_preset_outside_allowlist_is_rejected():
    with pytest.raises(tp.PlanError) as exc:
        planner().plan(job(preset="ultra"))
    assert exc.value.code == "bad_preset"


def test_crf_out_of_range_is_rejected():
    with pytest.raises(tp.PlanError) as exc:
        planner().plan(job(crf=60))
    assert exc.value.code == "bad_crf"


def test_crf_boolean_is_rejected():
    with pytest.raises(tp.PlanError) as exc:
        planner().plan(job(crf=True))
    assert exc.value.code == "bad_crf"


def test_unknown_job_field_is_rejected():
    with pytest.raises(tp.PlanError) as exc:
        planner().plan(job(extra_option="--x"))
    assert exc.value.code == "unknown_field"


def test_label_with_shell_characters_is_rejected():
    with pytest.raises(tp.PlanError) as exc:
        planner().plan(job(label="a;rm -rf /"))
    assert exc.value.code == "bad_label"


def test_run_passes_array_environment_and_limits():
    calls = []

    def runner(argv, env, timeout, cwd):
        calls.append((argv, env, timeout, cwd))
        return 0, "done"

    p = planner(runner=runner)
    plan = p.plan(job())
    out = p.run(plan)
    assert out["code"] == 0
    assert out["stdout"] == "done"
    argv, env, timeout, cwd = calls[0]
    assert argv == plan["argv"]
    assert env == {"PATH": "/usr/bin", "HOME": "/work"}
    assert timeout == 30
    assert cwd == "/work"


def test_tampered_plan_is_rejected():
    p = planner()
    plan = p.plan(job())
    plan["argv"] = ["sh", "-c", "id"]
    with pytest.raises(tp.PlanError) as exc:
        p.run(plan)
    assert exc.value.code == "tampered_plan"


def test_snapshot_counts_and_copy():
    p = planner(runner=lambda argv, env, timeout, cwd: (0, ""))
    plan = p.plan(job())
    p.run(plan)
    with pytest.raises(tp.PlanError):
        p.plan(job(preset="ultra"))
    snap = p.snapshot()
    assert snap["planned"] == 1
    assert snap["ran"] == 1
    assert snap["rejected"] == 1
    snap["planned"] = 0
    assert p.snapshot()["planned"] == 1
