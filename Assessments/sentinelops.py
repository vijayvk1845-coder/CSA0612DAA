"""SentinelOps SOC alert-triage module (corrected and optimised).

Functions
---------
sort_alerts            : stable sort of alerts by severity, highest first
sort_alerts_insertion  : corrected insertion-sort reference version (counts comparisons)
is_blocked             : corrected sequential search (single lookup)
build_blocklist_index  : builds a hash index for repeated lookups
is_blocked_indexed     : O(1) average lookup on the index
find_signature         : brute-force matching, every occurrence
closest_logins         : closest pair of login locations (pruned brute force)
closest_logins_bruteforce : corrected plain brute force (reference + counting)
"""
import math


def sort_alerts_insertion(alerts, stats=None):
    """Corrected insertion sort, severity descending, stable.

    alerts : list of (alert_id, severity) tuples, sorted in place.
    stats  : optional dict; stats['comparisons'] counts severity comparisons.
    Shifts only while the left item is STRICTLY lower, so equal severities
    keep their arrival order.
    """
    for i in range(1, len(alerts)):
        key = alerts[i]
        j = i - 1
        while j >= 0:                       # fix 1: j >= 0 (was j > 0)
            if stats is not None:
                stats["comparisons"] = stats.get("comparisons", 0) + 1
            if alerts[j][1] < key[1]:
                alerts[j + 1] = alerts[j]
                j -= 1
            else:
                break
        alerts[j + 1] = key                 # fix 2: j + 1 (was j)
    return alerts


def sort_alerts(alerts):
    """Sort alerts by severity, highest first; equal severities keep arrival order.

    Uses list.sort (Timsort): stable, O(n) on nearly sorted input and
    O(n log n) in the worst case. Sorts in place and returns the list.
    """
    alerts.sort(key=lambda a: -a[1])
    return alerts


def is_blocked(blocklist, ip):
    """Sequential search: True if ip is in blocklist, else False."""
    for entry in blocklist:
        if entry == ip:
            return True                     # fix 3: True on a match
    return False                            # fix 4: decided only after the whole list


def build_blocklist_index(blocklist):
    """Build a hash index once (O(b)) for many later lookups."""
    return frozenset(blocklist)


def is_blocked_indexed(index, ip):
    """O(1) average membership test on an index from build_blocklist_index."""
    return ip in index


def find_signature(log, pattern):
    """Return every start position of pattern in log (brute force).

    Returns [] for an empty pattern or a pattern longer than the log.
    Stops comparing an alignment at its first mismatch.
    """
    n, m = len(log), len(pattern)
    if m == 0 or m > n:
        return []
    hits = []
    for i in range(n - m + 1):              # fix 5: last alignment is n - m
        for j in range(m):
            if log[i + j] != pattern[j]:
                break
        else:                               # fix 6: no break => full match
            hits.append(i)
    return hits


def closest_logins_bruteforce(events, stats=None):
    """Corrected brute force: each unordered pair once, squared distances.

    Returns ((i, j), distance) with i < j, or (None, None) for < 2 events.
    Ties keep the first pair found in (i, j) order.
    """
    n = len(events)
    if n < 2:
        return None, None
    best, pair = None, None
    for i in range(n - 1):
        for j in range(i + 1, n):           # fix 8: j > i
            d2 = (events[i][0] - events[j][0]) ** 2 + (events[i][1] - events[j][1]) ** 2
            if stats is not None:
                stats["distances"] = stats.get("distances", 0) + 1
            if best is None or d2 < best:   # fix 7 and 9: start unset, keep SMALLER
                best, pair = d2, (i, j)
    return pair, math.sqrt(best)


def closest_logins(events, stats=None):
    """Closest pair of login locations; same output as the brute force.

    Sorts event indices by x and stops the inner loop once the x-gap alone
    exceeds the best squared distance (such pairs cannot be closer). Compares
    squared distances; one square root at the end.
    Returns ((i, j), distance) with i < j, or (None, None) for < 2 events.
    """
    n = len(events)
    if n < 2:
        return None, None
    order = sorted(range(n), key=lambda k: events[k][0])
    best = None                             # (squared distance, i, j)
    for p in range(n - 1):
        ip = order[p]
        xp, yp = events[ip]
        for q in range(p + 1, n):
            iq = order[q]
            dx = events[iq][0] - xp
            if best is not None and dx * dx > best[0]:
                break                       # all later points are even farther in x
            dy = events[iq][1] - yp
            d2 = dx * dx + dy * dy
            if stats is not None:
                stats["distances"] = stats.get("distances", 0) + 1
            a, b = (ip, iq) if ip < iq else (iq, ip)
            cand = (d2, a, b)               # tie -> smaller (i, j), as in brute force
            if best is None or cand < best:
                best = cand
    return (best[1], best[2]), math.sqrt(best[0])


def run_tests():
    """Test harness: every function, including the boundary cases."""
    import random
    # ---- sort_alerts
    alerts = [("A1", 3), ("A2", 9), ("A3", 5), ("A4", 9), ("A5", 1)]
    want = [("A2", 9), ("A4", 9), ("A3", 5), ("A1", 3), ("A5", 1)]
    assert sort_alerts(list(alerts)) == want
    assert sort_alerts_insertion(list(alerts)) == want
    assert sort_alerts([]) == [] and sort_alerts_insertion([]) == []
    assert sort_alerts([("X", 4)]) == [("X", 4)]
    eq = [("E1", 5), ("E2", 5), ("E3", 5)]
    assert sort_alerts(list(eq)) == eq and sort_alerts_insertion(list(eq)) == eq
    assert sort_alerts_insertion([("L", 1), ("H", 9)]) == [("H", 9), ("L", 1)]  # first item moves
    random.seed(1)
    for _ in range(200):
        data = [("I%d" % k, random.randint(1, 10)) for k in range(random.randint(0, 40))]
        assert sort_alerts(list(data)) == sort_alerts_insertion(list(data))
        assert sort_alerts(list(data)) == sorted(data, key=lambda a: -a[1])
    # ---- is_blocked
    bl = ["10.0.0.5", "10.0.0.9", "172.16.4.2"]
    idx = build_blocklist_index(bl)
    for ip, exp in (("10.0.0.9", True), ("10.0.0.5", True), ("172.16.4.2", True), ("8.8.8.8", False)):
        assert is_blocked(bl, ip) is exp and is_blocked_indexed(idx, ip) is exp
    assert is_blocked([], "10.0.0.5") is False and is_blocked_indexed(build_blocklist_index([]), "x") is False
    # ---- find_signature
    assert find_signature("FAILFAIXFAIL", "FAIL") == [0, 8]
    assert find_signature("XXFAIL", "FAIL") == [2]                 # pattern at the very end
    assert find_signature("FAIL", "FAIL") == [0]                   # pattern equals log
    assert find_signature("FA", "FAIL") == []                      # pattern longer than log
    assert find_signature("", "A") == [] and find_signature("ABC", "") == []
    assert find_signature("AAAA", "AA") == [0, 1, 2]               # overlapping hits
    assert find_signature("FAILFAIX", "FAIL") == [0]               # no false hit on FAIX
    # ---- closest_logins
    events = [(2, 3), (12, 30), (40, 50), (5, 1), (12, 10), (3, 4)]
    pair, dist = closest_logins(events)
    assert pair == (0, 5) and abs(dist - math.sqrt(2)) < 1e-12
    assert closest_logins_bruteforce(events) == (pair, dist)
    assert closest_logins([]) == (None, None) and closest_logins([(1, 1)]) == (None, None)
    assert closest_logins([(0, 0), (3, 4)]) == ((0, 1), 5.0)
    assert closest_logins([(1, 1), (1, 1), (9, 9)]) == ((0, 1), 0.0)   # duplicate points
    random.seed(2)
    for _ in range(300):
        ev = [(random.randint(0, 30), random.randint(0, 30)) for _ in range(random.randint(2, 40))]
        assert closest_logins(ev) == closest_logins_bruteforce(ev)
    print("All tests passed.")


if __name__ == "__main__":
    run_tests()
