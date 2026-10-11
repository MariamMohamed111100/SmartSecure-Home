"""Risk score with a decay window, a per-type repeat cap and correlation bonuses."""
from __future__ import annotations

from dataclasses import dataclass

from .policy import Policy

NON_PHYSICAL_ZONES = frozenset({"network"})


@dataclass
class Contribution:
    kind: str            # "event" | "correlation"
    type: str            # event type, or the correlation rule name
    points: int
    ts: float            # when the engine received it (the engine's own clock decides decay)
    zone: str
    event_id: str = ""


class Scorer:
    """Hard decay: an event counts in full until it is `window_s` old, then not at all."""

    def __init__(self, policy: Policy) -> None:
        self.policy = policy
        self.contribs: list[Contribution] = []
        self.seen: list[tuple[float, str]] = []          # (ts, type) of every scored event

    def purge(self, now: float) -> None:
        cutoff = now - self.policy.window_s
        self.contribs = [c for c in self.contribs if c.ts > cutoff]
        self.seen = [s for s in self.seen if s[0] > cutoff]

    def add_event(self, event_type: str, zone: str, event_id: str, now: float
                  ) -> Contribution | None:
        self.purge(now)
        points = self.policy.points.get(event_type, 0)
        if points <= 0:
            return None
        same = sum(1 for c in self.contribs if c.kind == "event" and c.type == event_type)
        if same >= self.policy.repeat_cap:
            return None
        self.seen.append((now, event_type))
        contrib = Contribution("event", event_type, points, now, zone, event_id)
        self.contribs.append(contrib)
        return contrib

    def correlate(self, now: float) -> list[Contribution]:
        """Add each rule's bonus once while its inputs are recent and the bonus is not alive."""
        fired: list[Contribution] = []
        for rule in self.policy.correlations:
            if any(c.kind == "correlation" and c.type == rule.name for c in self.contribs):
                continue
            recent = {t for ts, t in self.seen if now - ts <= rule.within_s}
            if all(t in recent for t in rule.requires):
                zone = next((c.zone for c in reversed(self.contribs)
                             if c.kind == "event" and c.type in rule.requires
                             and c.zone not in NON_PHYSICAL_ZONES), "network")
                bonus = Contribution("correlation", rule.name, rule.bonus, now, zone)
                self.contribs.append(bonus)
                fired.append(bonus)
        return fired

    def score(self, now: float) -> int:
        self.purge(now)
        return min(self.policy.max_score, sum(c.points for c in self.contribs))

    def factors(self, limit: int = 8) -> list[dict]:
        ranked = sorted(self.contribs, key=lambda c: (-c.points, c.ts))
        return [{"type": ("correlation." + c.type) if c.kind == "correlation" else c.type,
                 "weight": c.points} for c in ranked[:limit]]

    def main_zone(self) -> str | None:
        """The physical zone carrying the most points (latest wins a tie); None if only network."""
        totals: dict[str, tuple[int, float]] = {}
        for c in self.contribs:
            if c.zone in NON_PHYSICAL_ZONES:
                continue
            points, last = totals.get(c.zone, (0, 0.0))
            totals[c.zone] = (points + c.points, max(last, c.ts))
        return max(totals, key=lambda z: totals[z]) if totals else None

    def event_ids(self) -> list[str]:
        return [c.event_id for c in sorted(self.contribs, key=lambda c: c.ts)
                if c.kind == "event" and c.event_id]
