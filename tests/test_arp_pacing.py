"""Off-device test: the ARP sweep stays under switch ARP-inspection limits."""
import os
import sys
import threading
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import netdiag  # noqa: E402


class FakeClock:
    def __init__(self):
        self.t = 1000.0

    def now(self):
        return self.t

    def idle(self, sec):
        self.t += sec


class Job:
    def __init__(self):
        self.stop = threading.Event()


class ArpPacing(unittest.TestCase):
    def run_paced(self, n, pps):
        clock = FakeClock()
        real = netdiag.time.monotonic
        netdiag.time.monotonic = clock.now
        try:
            return [clock.t for _ in netdiag._paced(Job(), n, pps, clock.idle)]
        finally:
            netdiag.time.monotonic = real

    def test_rate_limits_are_below_dai_default(self):
        self.assertLess(netdiag.ARP_PPS, 15)
        self.assertLess(netdiag.ARP_KERNEL_PPS * 3, 15)   # kernel retries up to 3x

    def test_no_one_second_window_exceeds_the_limit(self):
        times = self.run_paced(253, netdiag.ARP_PPS)
        self.assertEqual(len(times), 253)
        worst = max(sum(1 for u in times if t <= u < t + 1.0) for t in times)
        self.assertLessEqual(worst, netdiag.ARP_PPS)
        self.assertLess(worst, 15)

    def test_stop_ends_early(self):
        job = Job()
        clock = FakeClock()
        real = netdiag.time.monotonic
        netdiag.time.monotonic = clock.now
        try:
            out = []
            for i in netdiag._paced(job, 100, 12, clock.idle):
                out.append(i)
                if i == 4:
                    job.stop.set()
            self.assertEqual(out, [0, 1, 2, 3, 4])
        finally:
            netdiag.time.monotonic = real


if __name__ == "__main__":
    unittest.main()
