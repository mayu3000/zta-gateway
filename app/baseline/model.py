"""Welford's online algorithm — running mean/variance with no raw history.

Each 30s window is folded into the device's running statistics, so memory use
is O(1) per device regardless of how long it's been observed ("lightweight").
"""
from app.models import db, DeviceBaseline
from app.baseline.config import MIN_SAMPLES_FOR_BASELINE


def _welford_update(mean, m2, count, new_value):
    """Return (mean, m2, count+1) after folding in new_value."""
    count += 1
    delta = new_value - mean
    mean += delta / count
    delta2 = new_value - mean
    m2 += delta * delta2
    return mean, m2, count


def update_baseline(mac, features):
    """Fold one window's features into this device's baseline; persist."""
    baseline = DeviceBaseline.query.filter_by(mac=mac).first()
    if not baseline:
        # Column defaults apply at INSERT, not to a new in-memory object, so
        # initialize explicitly (else the first Welford update sees None).
        baseline = DeviceBaseline(
            mac=mac, sample_count=0,
            packet_count_mean=0.0, packet_count_m2=0.0,
            byte_count_mean=0.0, byte_count_m2=0.0,
            unique_flow_mean=0.0, unique_flow_m2=0.0,
            dns_query_mean=0.0, dns_query_m2=0.0,
        )
        db.session.add(baseline)

    old_count = baseline.sample_count  # all four features share this window count

    baseline.packet_count_mean, baseline.packet_count_m2, new_count = _welford_update(
        baseline.packet_count_mean, baseline.packet_count_m2,
        old_count, features["packet_count"])

    baseline.byte_count_mean, baseline.byte_count_m2, _ = _welford_update(
        baseline.byte_count_mean, baseline.byte_count_m2,
        old_count, features["byte_count"])

    baseline.unique_flow_mean, baseline.unique_flow_m2, _ = _welford_update(
        baseline.unique_flow_mean, baseline.unique_flow_m2,
        old_count, features["unique_flow_count"])

    baseline.dns_query_mean, baseline.dns_query_m2, _ = _welford_update(
        baseline.dns_query_mean, baseline.dns_query_m2,
        old_count, features["dns_query_count"])

    baseline.sample_count = new_count
    if baseline.sample_count >= MIN_SAMPLES_FOR_BASELINE:
        baseline.learning_complete = True

    db.session.commit()
    return baseline


def get_std(m2, count):
    if count < 2:
        return 0.0
    return (m2 / (count - 1)) ** 0.5