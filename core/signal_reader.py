from core.risk_model import ActiveSignal
from core.signal_catalog import SignalSpec


def _flag_and_detail(value):
    """Signals are (flag, detail) tuples, or a bare bool. Anything else counts as 'not evaluated'."""
    if isinstance(value, tuple) and value:
        return value[0], (value[1] if len(value) > 1 else None)
    if isinstance(value, bool):
        return value, None
    return None, None


def read_signals(data, specs: list[SignalSpec], scope: str) -> list[ActiveSignal]:
    """Returns only the signals that are active (flag is True). None (not evaluated) and False are both inactive."""
    if data is None:
        return []
    active = []
    for spec in specs:
        flag, detail = _flag_and_detail(getattr(data, spec.name, None))
        if spec.detail_attr:
            detail = getattr(data, spec.detail_attr, detail)
        if flag is not True:
            continue
        lr = spec.lr_fn(detail) if spec.lr_fn else spec.lr
        active.append(ActiveSignal(spec.name, spec.module, spec.group, lr, detail, scope))
    return active


def format_detail(detail) -> str:
    if detail is None:
        return "n/a"
    if isinstance(detail, (list, tuple, set)):
        return ", ".join(str(item) for item in detail) or "n/a"
    return str(detail)