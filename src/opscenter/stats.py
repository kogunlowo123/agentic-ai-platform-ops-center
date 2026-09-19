"""Small statistics toolkit: percentiles, PSI and the two-sample Kolmogorov-Smirnov test."""

from __future__ import annotations

import math
from bisect import bisect_right
from collections import Counter
from collections.abc import Mapping, Sequence

_EPS = 1e-4


def mean(values: Sequence[float]) -> float:
    """Arithmetic mean. Raises ``ValueError`` on an empty sequence."""
    if not values:
        raise ValueError("mean of empty sequence")
    return sum(values) / len(values)


def stdev(values: Sequence[float]) -> float:
    """Sample standard deviation (0.0 for fewer than two values)."""
    if len(values) < 2:
        return 0.0
    mu = mean(values)
    return math.sqrt(sum((v - mu) ** 2 for v in values) / (len(values) - 1))


def percentile(values: Sequence[float], q: float) -> float:
    """Linear-interpolated percentile, ``q`` in [0, 1]. Raises ``ValueError`` on an empty sequence."""
    if not values:
        raise ValueError("percentile of empty sequence")
    if not 0.0 <= q <= 1.0:
        raise ValueError("q must be between 0 and 1")
    ordered = sorted(values)
    position = (len(ordered) - 1) * q
    low, high = math.floor(position), math.ceil(position)
    if low == high:
        return ordered[low]
    return ordered[low] + (ordered[high] - ordered[low]) * (position - low)


def _shares(counts: Sequence[int]) -> list[float]:
    total = sum(counts) or 1
    return [max(c / total, _EPS) for c in counts]


def _psi_from_counts(base: Sequence[int], current: Sequence[int]) -> float:
    b, c = _shares(base), _shares(current)
    return sum((cs - bs) * math.log(cs / bs) for bs, cs in zip(b, c, strict=True))


def _sign_counts(values: Sequence[float], anchor: float) -> list[int]:
    """Counts of values below, equal to and above ``anchor``."""
    return [
        sum(1 for v in values if v < anchor),
        sum(1 for v in values if v == anchor),
        sum(1 for v in values if v > anchor),
    ]


def psi(baseline: Sequence[float], current: Sequence[float], bins: int = 10) -> float:
    """Population Stability Index of ``current`` against ``baseline``.

    Bin edges are the baseline's quantiles, so each bin holds about 1/``bins`` of the baseline. Rule
    of thumb: below 0.1 stable, 0.1 to 0.25 moderate shift, above 0.25 significant shift.
    """
    if not baseline or not current:
        raise ValueError("psi needs non-empty samples")
    if len(set(baseline)) == 1:
        # Quantile edges collapse for a constant baseline, so compare against that single value.
        anchor = baseline[0]
        return _psi_from_counts(_sign_counts(baseline, anchor), _sign_counts(current, anchor))
    edges = sorted({percentile(baseline, i / bins) for i in range(1, bins)})
    base_counts = [0] * (len(edges) + 1)
    cur_counts = [0] * (len(edges) + 1)
    for value in baseline:
        base_counts[bisect_right(edges, value)] += 1
    for value in current:
        cur_counts[bisect_right(edges, value)] += 1
    return _psi_from_counts(base_counts, cur_counts)


def psi_categorical(baseline: Mapping[str, int], current: Mapping[str, int]) -> float:
    """PSI over category counts (categories missing from one side count as zero)."""
    keys = sorted(set(baseline) | set(current))
    return _psi_from_counts([baseline.get(k, 0) for k in keys], [current.get(k, 0) for k in keys])


def ks_two_sample(a: Sequence[float], b: Sequence[float]) -> tuple[float, float]:
    """Two-sample Kolmogorov-Smirnov statistic ``D`` and an asymptotic p-value."""
    if not a or not b:
        raise ValueError("ks needs non-empty samples")
    xs, ys = sorted(a), sorted(b)
    n, m = len(xs), len(ys)
    i = j = 0
    d = 0.0
    while i < n and j < m:
        value = min(xs[i], ys[j])
        while i < n and xs[i] <= value:
            i += 1
        while j < m and ys[j] <= value:
            j += 1
        d = max(d, abs(i / n - j / m))
    effective = math.sqrt(n * m / (n + m))
    lam = (effective + 0.12 + 0.11 / effective) * d
    if lam < 1e-9:
        return d, 1.0
    p = 2 * sum((-1) ** (k - 1) * math.exp(-2 * k * k * lam * lam) for k in range(1, 101))
    return d, min(max(p, 0.0), 1.0)


def category_counts(values: Sequence[str]) -> dict[str, int]:
    """Counts of each distinct value."""
    return dict(Counter(values))
