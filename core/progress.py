import threading
import time

_LOCK = threading.RLock()
_TRACKERS: dict[str, dict] = {}
_LOCAL = threading.local()
_TTL_SECONDS = 900
_MAX_TRACKERS = 200

_URL_STAGES = (
    ("url_m1", "Analysing the domain and its redirects", 2),
    ("url_m5", "Inspecting the website", 1),
    ("tls", "Reading the security certificates", 1),
)


def _stage(stage_id: str, label: str, weight: int = 1) -> dict:
    return {"id": stage_id, "label": label, "status": "pending", "detail": None, "weight": weight, "_n": 0, "_total": None}


def _find(tracker: dict, stage_id: str) -> dict | None:
    return next((s for s in tracker["stages"] if s["id"] == stage_id), None)


def _prune() -> None:
    now = time.time()
    for key in [k for k, t in _TRACKERS.items() if now - t["updated"] > _TTL_SECONDS]:
        del _TRACKERS[key]
    while len(_TRACKERS) > _MAX_TRACKERS:
        del _TRACKERS[min(_TRACKERS, key=lambda k: _TRACKERS[k]["updated"])]


def _insert_after(tracker: dict, after_id: str | None, stages: list[dict]) -> None:
    index = next((i for i, s in enumerate(tracker["stages"]) if s["id"] == after_id), None)
    position = 0 if index is None else index + 1
    tracker["stages"][position:position] = stages


def begin(investigation_id: str, investigation_type: str) -> None:
    """Create the progress record with the stages that are already known for this kind of investigation."""
    stages: list[dict] = []
    if investigation_type in ("message", "combined"):
        stages.append(_stage("m3", "Reading the message and pulling out links, numbers and addresses"))
    if investigation_type in ("url", "combined"):
        stages += [_stage(*s) for s in _URL_STAGES]
    stages += [
        _stage("corr", "Comparing with earlier investigations"),
        _stage("assess", "Weighing the evidence and writing the explanation", 3),
        _stage("chain", "Recording the report on the blockchain", 2),
    ]
    with _LOCK:
        _prune()
        _TRACKERS[investigation_id] = {"stages": stages, "finished": False, "failed": False, "updated": time.time()}
    _LOCAL.current = investigation_id


def _with(investigation_id, stage_id, change) -> None:
    with _LOCK:
        tracker = _TRACKERS.get(investigation_id)
        stage = _find(tracker, stage_id) if tracker else None
        if stage is not None and stage["status"] != "skipped":
            change(stage)
            tracker["updated"] = time.time()


def start(investigation_id: str, stage_id: str) -> None:
    def change(s):
        if s["status"] == "pending":
            s["status"] = "running"
    _with(investigation_id, stage_id, change)


def done(investigation_id: str, stage_id: str, detail: str | None = None) -> None:
    def change(s):
        s["status"] = "done"
        if detail:
            s["detail"] = detail
    _with(investigation_id, stage_id, change)


def skip(investigation_id: str, stage_id: str) -> None:
    with _LOCK:
        tracker = _TRACKERS.get(investigation_id)
        stage = _find(tracker, stage_id) if tracker else None
        if stage is not None and stage["status"] == "pending":
            stage["status"] = "skipped"


def set_total(investigation_id: str, stage_id: str, total: int) -> None:
    def change(s):
        s["_total"] = total
        s["status"] = "running" if s["status"] == "pending" else s["status"]
        s["detail"] = f"0 of {total}" if total > 1 else None
    _with(investigation_id, stage_id, change)


def tick(investigation_id: str, stage_id: str) -> None:
    """One unit of a stage finished (safe to call from worker threads)."""
    def change(s):
        s["_n"] += 1
        if s["status"] == "pending":
            s["status"] = "running"
        total = s["_total"]
        if total:
            s["detail"] = f"{min(s['_n'], total)} of {total}" if total > 1 else None
            if s["_n"] >= total:
                s["status"] = "done"
    _with(investigation_id, stage_id, change)


def urls_found(investigation_id: str, count: int, from_message: bool = False) -> None:
    """The links to analyse are known: add the URL stages if they are missing and set their totals."""
    if count <= 0:
        return
    with _LOCK:
        tracker = _TRACKERS.get(investigation_id)
        if not tracker:
            return
        if _find(tracker, "url_m1") is None:
            _insert_after(tracker, "m3", [_stage(*s) for s in _URL_STAGES])
        if from_message:
            _find(tracker, "url_m1")["label"] = "Analysing the links found in the message"
            _find(tracker, "url_m5")["label"] = "Inspecting the linked websites"
    set_total(investigation_id, "url_m1", count)
    with _LOCK:
        stage = _find(_TRACKERS[investigation_id], "url_m5")
        stage["_total"] = count
        stage["detail"] = None


def redirects(investigation_id: str, count: int) -> None:
    """Redirects were observed: show them as a finished step between the site and certificate stages."""
    if count <= 0:
        return
    with _LOCK:
        tracker = _TRACKERS.get(investigation_id)
        if not tracker or _find(tracker, "redirects"):
            return
        done_stage = _stage("redirects", f"Followed {count} redirect{'s' if count != 1 else ''} to the final destination", 0)
        done_stage["status"] = "done"
        _insert_after(tracker, "url_m5", [done_stage])


def tls_planned(investigation_id: str, count: int) -> None:
    if count <= 0:
        skip(investigation_id, "tls")
    else:
        set_total(investigation_id, "tls", count)


def finish(investigation_id: str) -> None:
    with _LOCK:
        tracker = _TRACKERS.get(investigation_id)
        if not tracker:
            return
        for s in tracker["stages"]:
            s["status"] = "done" if s["status"] == "running" else "skipped" if s["status"] == "pending" else s["status"]
        tracker.update(finished=True, updated=time.time())


def fail_current() -> None:
    investigation_id = getattr(_LOCAL, "current", None)
    with _LOCK:
        tracker = _TRACKERS.get(investigation_id) if investigation_id else None
        if tracker:
            tracker.update(finished=True, failed=True, updated=time.time())


def release_current() -> None:
    _LOCAL.current = None


def snapshot(investigation_id: str) -> dict | None:
    with _LOCK:
        tracker = _TRACKERS.get(investigation_id)
        if not tracker:
            return None
        return {
            "stages": [{k: v for k, v in s.items() if not k.startswith("_")} for s in tracker["stages"]],
            "finished": tracker["finished"],
            "failed": tracker["failed"],
        }