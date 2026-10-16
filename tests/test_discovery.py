"""Discovery / Wi-Fi-station guard tests.

Regression coverage for the bug where `get_wifi_stations()` returned an empty
set (instead of None) on a wired interface, causing scan_network() to filter
out every discovered device.

The real-world signal being modelled: on a wired NIC,
  * `iw dev <iface> info`     -> exit 1, "command failed: No such device (-19)"
  * `iw dev <iface> station dump` -> exit 0, no output
"""
import os
import sys
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app import discovery


def _proc(returncode, stdout=""):
    m = MagicMock()
    m.returncode = returncode
    m.stdout = stdout
    return m


def _fake_iw(info_rc, info_out, dump_rc, dump_out):
    """Return a subprocess.run side_effect for the two iw invocations."""
    def _run(args, **_kw):
        # args == ["iw", "dev", <iface>, <subcmd>, ...]
        sub = args[1:4]
        if sub[2] == "info":
            return _proc(info_rc, info_out)
        return _proc(dump_rc, dump_out)
    return _run


class WifiStationGuardTests(unittest.TestCase):
    def setUp(self):
        # Force the Linux code path regardless of the host OS.
        self._orig_is_linux = discovery._IS_LINUX
        discovery._IS_LINUX = True

    def tearDown(self):
        discovery._IS_LINUX = self._orig_is_linux

    def test_wired_iface_returns_none_even_when_dump_is_empty(self):
        """Wired NIC: info -> ENODEV, station dump -> exit 0 empty.

        Must return None (not set()), otherwise scan_network filters everything.
        """
        runner = _fake_iw(1, "command failed: No such device (-19)\n", 0, "")
        with patch.object(discovery.subprocess, "run", side_effect=runner):
            self.assertIsNone(discovery.get_wifi_stations("eth1"))

    def test_windows_returns_none(self):
        discovery._IS_LINUX = False
        with patch.object(discovery.subprocess, "run") as run:
            self.assertIsNone(discovery.get_wifi_stations("eth1"))
            run.assert_not_called()

    def test_real_ap_with_clients_returns_macs(self):
        dump = ("Station aa:bb:cc:dd:ee:ff (on wlan0)\n"
                "\tinactive time:\t0 ms\n"
                "Station 11:22:33:44:55:66 (on wlan0)\n")
        runner = _fake_iw(0, "Interface wlan0\n\ttype AP\n", 0, dump)
        with patch.object(discovery.subprocess, "run", side_effect=runner):
            self.assertEqual(discovery.get_wifi_stations("wlan0"),
                             {"aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"})

    def test_real_ap_with_no_clients_returns_empty_set(self):
        """A genuine AP with zero clients still filters everything (by design)."""
        runner = _fake_iw(0, "Interface wlan0\n\ttype AP\n", 0, "")
        with patch.object(discovery.subprocess, "run", side_effect=runner):
            self.assertEqual(discovery.get_wifi_stations("wlan0"), set())

    def test_missing_iw_returns_none(self):
        with patch.object(discovery.subprocess, "run",
                          side_effect=FileNotFoundError):
            self.assertIsNone(discovery.get_wifi_stations("eth1"))

    def test_scan_network_keeps_devices_on_wired_iface(self):
        """End-to-end: a wired iface must not filter discovered devices."""
        devices = [{"ip": "192.168.50.98", "mac": "aa:bb:cc:dd:ee:ff"},
                   {"ip": "192.168.50.50", "mac": "11:22:33:44:55:66"}]
        runner = _fake_iw(1, "command failed: No such device (-19)\n", 0, "")
        with patch.object(discovery, "scan_network_scapy", return_value=devices), \
             patch.object(discovery, "_scan_ping_arp", return_value=[]), \
             patch.object(discovery, "local_ip_macs", return_value={}), \
             patch.object(discovery.subprocess, "run", side_effect=runner):
            found = discovery.scan_network(iface="eth1")
        self.assertEqual(len(found), 2)

    def test_scan_network_filters_when_real_ap_has_no_clients(self):
        """Positive control: a genuine AP with zero clients still hides all."""
        devices = [{"ip": "192.168.50.98", "mac": "aa:bb:cc:dd:ee:ff"}]
        runner = _fake_iw(0, "Interface wlan0\n\ttype AP\n", 0, "")
        with patch.object(discovery, "scan_network_scapy", return_value=devices), \
             patch.object(discovery, "_scan_ping_arp", return_value=[]), \
             patch.object(discovery, "local_ip_macs", return_value={}), \
             patch.object(discovery.subprocess, "run", side_effect=runner):
            self.assertEqual(discovery.scan_network(iface="wlan0"), [])

    def test_scan_network_unions_scapy_and_neighbour_table(self):
        """A device seen by only one sensor is still discovered, with no dupes."""
        scapy = [{"ip": "192.168.50.50", "mac": "11:22:33:44:55:66"}]
        neigh = [{"ip": "192.168.50.98", "mac": "aa:bb:cc:dd:ee:ff"},
                 {"ip": "192.168.50.50", "mac": "11:22:33:44:55:66"}]
        with patch.object(discovery, "scan_network_scapy", return_value=scapy), \
             patch.object(discovery, "_scan_ping_arp", return_value=neigh), \
             patch.object(discovery, "get_wifi_stations", return_value=None), \
             patch.object(discovery, "local_ip_macs", return_value={}):
            found = discovery.scan_network(iface="eth1")
        self.assertEqual(sorted(d["mac"] for d in found),
                         ["11:22:33:44:55:66", "aa:bb:cc:dd:ee:ff"])

    def test_scan_network_unions_when_scapy_raises(self):
        neigh = [{"ip": "192.168.50.98", "mac": "aa:bb:cc:dd:ee:ff"}]
        with patch.object(discovery, "scan_network_scapy",
                          side_effect=OSError("no raw socket")), \
             patch.object(discovery, "_scan_ping_arp", return_value=neigh), \
             patch.object(discovery, "get_wifi_stations", return_value=None), \
             patch.object(discovery, "local_ip_macs", return_value={}):
            found = discovery.scan_network(iface="eth1")
        self.assertEqual([d["mac"] for d in found], ["aa:bb:cc:dd:ee:ff"])

    def test_scan_network_excludes_gateway_itself(self):
        """The gateway's own adapter must never be registered as a device."""
        own = [{"ip": "192.168.50.1", "mac": "de:ad:be:ef:00:01"}]
        with patch.object(discovery, "scan_network_scapy", return_value=own), \
             patch.object(discovery, "_scan_ping_arp", return_value=[]), \
             patch.object(discovery, "get_wifi_stations", return_value=None), \
             patch.object(discovery, "local_ip_macs",
                          return_value={"192.168.50.1": "de:ad:be:ef:00:01"}):
            self.assertEqual(discovery.scan_network(iface="eth1"), [])


if __name__ == "__main__":
    unittest.main()
