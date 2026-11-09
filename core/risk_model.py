"""
Evidence-combination model for the assessment engine.

Idea: work in odds. Start from a prior, multiply by a likelihood ratio (LR) for each signal that is present.
LR = P(signal | malicious) / P(signal | benign). Absent signals contribute nothing, because the absence of a
known threat is not evidence of safety.

Two things stop plain multiplication from misleading:
  1. Correlated signals. Typosquatting and brand-in-subdomain are two views of one fact. Signals sharing an
     evidence group are discounted: strongest counts fully, the next 40%, then 16%, and so on.
  2. Combinations. Some pairings are far more telling than either signal alone (a lookalike domain registered
     last week). These are explicit Interaction rules with their own LR, evaluated within a single URL.

The LRs in signal_catalog.py are expert estimates, not learned values. Treat the output as a ranked score and
calibrate it on labelled cases before quoting it as a probability.
"""
import math
from dataclasses import dataclass, field


@dataclass(frozen=True)
class ActiveSignal:
    name: str
    module: str
    group: str | None  # evidence group; None = reported but not scored
    lr: float | None  # likelihood ratio; None = not scored
    detail: object
    scope: str  # "message", "global", or the URL reference this signal belongs to


@dataclass(frozen=True)
class Interaction:
    name: str
    title: str
    # Each entry is a signal/group name that must be active, or a tuple of names of which at least one must be.
    requires: tuple
    lr: float
    description: str


@dataclass
class FiredInteraction:
    name: str
    title: str
    lr: float
    description: str
    scope: str | None
    members: list[str]


@dataclass
class RiskModelConfig:
    prior: float = 0.10  # P(malicious) for something a person chose to submit, before any evidence
    group_discount: float = 0.4
    suspicious_threshold: float = 0.40
    high_threshold: float = 0.85
    # Evidence that is only wording or only certificate configuration cannot reach High on its own.
    capped_groups: frozenset = frozenset({"message_language", "message_impersonation", "tls_trust", "transport"})
    cap_probability: float = 0.80


@dataclass
class RiskScore:
    prior: float
    probability: float
    log_odds: float
    group_lr: dict[str, float] = field(default_factory=dict)  # evidence group -> combined LR after discounting
    signal_lr: list[tuple[str, float]] = field(default_factory=list)  # (signal, its own LR), strongest first
    interactions: list[FiredInteraction] = field(default_factory=list)
    capped: bool = False
    cap_reason: str | None = None


class RiskModel:
    def __init__(self, config: RiskModelConfig | None = None):
        self.config = config or RiskModelConfig()

    def score(self, signals: list[ActiveSignal], interactions: list[Interaction]) -> RiskScore:
        cfg = self.config
        scored = [s for s in signals if s.group and s.lr and s.lr > 0]

        # 1. Discount correlated signals inside each group
        by_group: dict[str, list[float]] = {}
        for s in scored:
            by_group.setdefault(s.group, []).append(math.log(s.lr))
        group_log: dict[str, float] = {}
        for group, logs in by_group.items():
            logs.sort(reverse=True)
            group_log[group] = sum(value * (cfg.group_discount ** i) for i, value in enumerate(logs))

        # 2. Interactions
        fired = self._fire_interactions(scored, interactions)

        prior_log_odds = math.log(cfg.prior / (1 - cfg.prior))
        log_odds = prior_log_odds + sum(group_log.values()) + sum(math.log(f.lr) for f in fired)
        probability = 1 / (1 + math.exp(-log_odds))

        # 3. Cap evidence types that are not proof of an attack on their own
        capped, reason = False, None
        active_groups = {s.group for s in scored}
        if active_groups and active_groups <= cfg.capped_groups and probability > cfg.cap_probability:
            probability, capped = cfg.cap_probability, True
            reason = ("Only message wording and/or certificate configuration was found; "
                      "that is not enough on its own for a High rating.")

        return RiskScore(
            prior=cfg.prior,
            probability=probability,
            log_odds=log_odds,
            group_lr={g: math.exp(v) for g, v in group_log.items()},
            signal_lr=sorted(((s.name, s.lr) for s in scored), key=lambda item: -item[1]),
            interactions=fired,
            capped=capped,
            cap_reason=reason,
        )

    def level_label(self, probability: float) -> str:
        if probability >= self.config.high_threshold:
            return "high"
        if probability >= self.config.suspicious_threshold:
            return "suspicious"
        return "low"

    @staticmethod
    def _fire_interactions(scored: list[ActiveSignal], interactions: list[Interaction]) -> list[FiredInteraction]:
        shared = {"message", "global"}
        url_scopes = sorted({s.scope for s in scored if s.scope not in shared})

        def available(scope: str | None) -> set[str]:
            names: set[str] = set()
            for s in scored:
                if s.scope in shared or s.scope == scope:
                    names.add(s.name)
                    if s.group:
                        names.add(s.group)
            return names

        fired = []
        for rule in interactions:
            # A combination must hold inside ONE URL (plus the message and global evidence),
            # so a lookalike on link A and a new domain on link B do not combine.
            for scope in (url_scopes or [None]):
                names = available(scope)
                members = []
                satisfied = True
                for requirement in rule.requires:
                    options = (requirement,) if isinstance(requirement, str) else requirement
                    hit = [o for o in options if o in names]
                    if not hit:
                        satisfied = False
                        break
                    members.append(hit[0])
                if satisfied:
                    fired.append(FiredInteraction(rule.name, rule.title, rule.lr, rule.description, scope, members))
                    break
        return fired