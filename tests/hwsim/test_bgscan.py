# bgscan tests
# Copyright (c) 2014-2017, Jouni Malinen <j@w1.fi>
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import time
import logging
logger = logging.getLogger()
import os

import hostapd
from utils import alloc_fail, fail_test, wait_fail_trigger

def test_bgscan_simple(dev, apdev):
    """bgscan_simple"""
    hostapd.add_ap(apdev[0], {"ssid": "bgscan"})
    hostapd.add_ap(apdev[1], {"ssid": "bgscan"})

    dev[0].connect("bgscan", key_mgmt="NONE", scan_freq="2412",
                   bgscan="simple:1:-20:2")
    dev[1].connect("bgscan", key_mgmt="NONE", scan_freq="2412",
                   bgscan="simple:1:-45:2")

    dev[2].connect("bgscan", key_mgmt="NONE", scan_freq="2412",
                   bgscan="simple:1:-45")
    dev[2].request("REMOVE_NETWORK all")
    dev[2].wait_disconnected()

    dev[2].connect("bgscan", key_mgmt="NONE", scan_freq="2412",
                   bgscan="simple:0:0")
    dev[2].request("REMOVE_NETWORK all")
    dev[2].wait_disconnected()

    dev[2].connect("bgscan", key_mgmt="NONE", scan_freq="2412",
                   bgscan="simple")
    dev[2].request("REMOVE_NETWORK all")
    dev[2].wait_disconnected()

    dev[2].connect("bgscan", key_mgmt="NONE", scan_freq="2412",
                   bgscan="simple:1")
    dev[2].request("REMOVE_NETWORK all")
    dev[2].wait_disconnected()

    ev = dev[0].wait_event(["CTRL-EVENT-SIGNAL-CHANGE"], timeout=10)
    if ev is None:
        raise Exception("dev0 did not indicate signal change event")
    if "above=0" not in ev:
        raise Exception("Unexpected signal change event contents from dev0: " + ev)

    ev = dev[1].wait_event(["CTRL-EVENT-SIGNAL-CHANGE"], timeout=10)
    if ev is None:
        raise Exception("dev1 did not indicate signal change event")
    if "above=1" not in ev:
        raise Exception("Unexpected signal change event contents from dev1: " + ev)

    ev = dev[0].wait_event(["CTRL-EVENT-SCAN-STARTED"], timeout=3)
    if ev is None:
        raise Exception("dev0 did not start a scan")

    ev = dev[1].wait_event(["CTRL-EVENT-SCAN-STARTED"], timeout=3)
    if ev is None:
        raise Exception("dev1 did not start a scan")

    ev = dev[0].wait_event(["CTRL-EVENT-SCAN-RESULTS"], 5)
    if ev is None:
        raise Exception("dev0 did not complete a scan")
    ev = dev[1].wait_event(["CTRL-EVENT-SCAN-RESULTS"], 5)
    if ev is None:
        raise Exception("dev1 did not complete a scan")

def test_bgscan_simple_beacon_loss(dev, apdev):
    """bgscan_simple and beacon loss"""
    params = hostapd.wpa2_params(ssid="bgscan", passphrase="12345678")
    params["wpa_key_mgmt"] = "WPA-PSK-SHA256"
    params["ieee80211w"] = "2"
    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].set("disable_sa_query", "1")
    dev[0].connect("bgscan", ieee80211w="2", key_mgmt="WPA-PSK-SHA256",
                   psk="12345678", scan_freq="2412",
                   bgscan="simple:100:-20:200")
    hapd.set("ext_mgmt_frame_handling", "1")
    if "OK" not in hapd.request("STOP_AP"):
        raise Exception("Failed to stop AP")
    hapd.disable()
    hapd.set("ssid", "foo")
    hapd.set("beacon_int", "10000")
    hapd.enable()
    ev = dev[0].wait_event(["CTRL-EVENT-BEACON-LOSS"], timeout=10)
    if ev is None:
        raise Exception("Beacon loss not reported")

def test_bgscan_simple_scan_failure(dev, apdev):
    """bgscan_simple and scan failure"""
    hapd = hostapd.add_ap(apdev[0], {"ssid": "bgscan"})

    dev[0].connect("bgscan", key_mgmt="NONE", scan_freq="2412",
                   bgscan="simple:1:-20:2")
    with alloc_fail(dev[0], 1,
                    "wpa_supplicant_trigger_scan;bgscan_simple_timeout"):
        wait_fail_trigger(dev[0], "GET_ALLOC_FAIL")
    ev = dev[0].wait_event(["CTRL-EVENT-SCAN-RESULTS"], 10)
    if ev is None:
        raise Exception("Scanning not continued after failure")

def test_bgscan_simple_scanning(dev, apdev):
    """bgscan_simple and scanning behavior"""
    hapd = hostapd.add_ap(apdev[0], {"ssid": "bgscan"})

    dev[0].connect("bgscan", key_mgmt="NONE", scan_freq="2412",
                   bgscan="simple:1:-20:2")
    # Go through seven bgscan_simple_timeout calls for code coverage. This falls
    # back from short to long scan interval and then reduces short_scan_count
    # back to zero.
    for i in range(7):
        ev = dev[0].wait_event(["CTRL-EVENT-SCAN-RESULTS"], 10)
        if ev is None:
            raise Exception("Scanning not continued")

def test_bgscan_simple_same_scan_int(dev, apdev):
    """bgscan_simple and same short/long scan interval"""
    hapd = hostapd.add_ap(apdev[0], {"ssid": "bgscan"})

    dev[0].connect("bgscan", key_mgmt="NONE", scan_freq="2412",
                   bgscan="simple:1:-20:1")
    for i in range(2):
        ev = dev[0].wait_event(["CTRL-EVENT-SCAN-RESULTS"], 10)
        if ev is None:
            raise Exception("Scanning not continued")

def test_bgscan_simple_btm_query(dev, apdev):
    """bgscan_simple and BTM query"""
    params = {"ssid": "bgscan",
              "bss_transition": "1"}
    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect("bgscan", key_mgmt="NONE", scan_freq="2412",
                   bgscan="simple:1:-20:1:2")
    ev = dev[0].wait_event(["WNM: BSS Transition Management Request"], 10)
    if ev is None:
        raise Exception("BSS TM not used")
    for i in range(2):
        ev = dev[0].wait_event(["CTRL-EVENT-SCAN-RESULTS"], 10)
        if ev is None:
            raise Exception("Scanning not continued")

def test_bgscan_simple_btm_query_no_ap_support(dev, apdev):
    """bgscan_simple and BTM query and no AP support"""
    params = {"ssid": "bgscan",
              "bss_transition": "0"}
    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect("bgscan", key_mgmt="NONE", scan_freq="2412",
                   bgscan="simple:1:-20:1:2")
    ev = dev[0].wait_event(["WNM: BSS Transition Management Request",
                            "CTRL-EVENT-SCAN-RESULTS"], 10)
    if ev is None:
        raise Exception("No background scan seen")
    if "WNM: BSS" in ev:
        raise Exception("Unexpected use of BSS TM")

def test_bgscan_simple_oom(dev, apdev):
    """bgscan_simple OOM"""
    hapd = hostapd.add_ap(apdev[0], {"ssid": "bgscan"})

    with alloc_fail(dev[0], 1, "bgscan_simple_init"):
        dev[0].connect("bgscan", key_mgmt="NONE", scan_freq="2412",
                       bgscan="simple:1:-20:2")

def test_bgscan_simple_driver_conf_failure(dev, apdev):
    """bgscan_simple driver configuration failure"""
    hapd = hostapd.add_ap(apdev[0], {"ssid": "bgscan"})

    with fail_test(dev[0], 1, "bgscan_simple_init"):
        dev[0].connect("bgscan", key_mgmt="NONE", scan_freq="2412",
                       bgscan="simple:1:-20:2")

def test_bgscan_learn(dev, apdev):
    """bgscan_learn"""
    hostapd.add_ap(apdev[0], {"ssid": "bgscan"})
    hostapd.add_ap(apdev[1], {"ssid": "bgscan"})

    try:
        os.remove("/tmp/test_bgscan_learn.bgscan")
    except:
        pass

    try:
        dev[0].connect("bgscan", key_mgmt="NONE", scan_freq="2412",
                       bgscan="learn:1:-20:2")
        id = dev[1].connect("bgscan", key_mgmt="NONE", scan_freq="2412",
                            bgscan="learn:1:-45:2:/tmp/test_bgscan_learn.bgscan")

        dev[2].connect("bgscan", key_mgmt="NONE", scan_freq="2412",
                       bgscan="learn:1:-45")
        dev[2].request("REMOVE_NETWORK all")
        dev[2].wait_disconnected()

        dev[2].connect("bgscan", key_mgmt="NONE", scan_freq="2412",
                       bgscan="learn:0:0")
        dev[2].request("REMOVE_NETWORK all")
        dev[2].wait_disconnected()

        dev[2].connect("bgscan", key_mgmt="NONE", scan_freq="2412",
                       bgscan="learn")
        dev[2].request("REMOVE_NETWORK all")
        dev[2].wait_disconnected()

        dev[2].connect("bgscan", key_mgmt="NONE", scan_freq="2412",
                       bgscan="learn:1")
        dev[2].request("REMOVE_NETWORK all")
        dev[2].wait_disconnected()

        ev = dev[0].wait_event(["CTRL-EVENT-SIGNAL-CHANGE"], timeout=10)
        if ev is None:
            raise Exception("dev0 did not indicate signal change event")
        if "above=0" not in ev:
            raise Exception("Unexpected signal change event contents from dev0: " + ev)

        ev = dev[1].wait_event(["CTRL-EVENT-SIGNAL-CHANGE"], timeout=10)
        if ev is None:
            raise Exception("dev1 did not indicate signal change event")
        if "above=1" not in ev:
            raise Exception("Unexpected signal change event contents from dev1: " + ev)

        ev = dev[0].wait_event(["CTRL-EVENT-SCAN-STARTED"], timeout=3)
        if ev is None:
            raise Exception("dev0 did not start a scan")

        ev = dev[1].wait_event(["CTRL-EVENT-SCAN-STARTED"], timeout=3)
        if ev is None:
            raise Exception("dev1 did not start a scan")

        ev = dev[0].wait_event(["CTRL-EVENT-SCAN-RESULTS"], 5)
        if ev is None:
            raise Exception("dev0 did not complete a scan")
        ev = dev[1].wait_event(["CTRL-EVENT-SCAN-RESULTS"], 5)
        if ev is None:
            raise Exception("dev1 did not complete a scan")

        dev[0].request("DISCONNECT")
        dev[1].request("DISCONNECT")
        dev[0].request("REMOVE_NETWORK all")

        with open("/tmp/test_bgscan_learn.bgscan", "r") as f:
            lines = f.read().splitlines()
        if lines[0] != "wpa_supplicant-bgscan-learn":
            raise Exception("Unexpected bgscan header line")
        if 'BSS 02:00:00:00:03:00 2412' not in lines:
            raise Exception("Missing BSS1")
        if 'BSS 02:00:00:00:04:00 2412' not in lines:
            raise Exception("Missing BSS2")
        if 'NEIGHBOR 02:00:00:00:03:00 02:00:00:00:04:00' not in lines:
            raise Exception("Missing BSS1->BSS2 neighbor entry")
        if 'NEIGHBOR 02:00:00:00:04:00 02:00:00:00:03:00' not in lines:
            raise Exception("Missing BSS2->BSS1 neighbor entry")

        dev[1].set_network(id, "scan_freq", "")
        dev[1].connect_network(id)

        ev = dev[1].wait_event(["CTRL-EVENT-SCAN-STARTED"], timeout=10)
        if ev is None:
            raise Exception("dev1 did not start a scan")

        ev = dev[1].wait_event(["CTRL-EVENT-SCAN-RESULTS"], 10)
        if ev is None:
            raise Exception("dev1 did not complete a scan")

        dev[1].request("REMOVE_NETWORK all")
    finally:
        try:
            os.remove("/tmp/test_bgscan_learn.bgscan")
        except:
            pass

def test_bgscan_learn_beacon_loss(dev, apdev):
    """bgscan_simple and beacon loss"""
    params = hostapd.wpa2_params(ssid="bgscan", passphrase="12345678")
    params["wpa_key_mgmt"] = "WPA-PSK-SHA256"
    params["ieee80211w"] = "2"
    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].set("disable_sa_query", "1")
    dev[0].connect("bgscan", ieee80211w="2", key_mgmt="WPA-PSK-SHA256",
                   psk="12345678", scan_freq="2412", bgscan="learn:100:-20:200")
    hapd.set("ext_mgmt_frame_handling", "1")
    if "OK" not in hapd.request("STOP_AP"):
        raise Exception("Failed to stop AP")
    hapd.disable()
    hapd.set("ssid", "foo")
    hapd.set("beacon_int", "10000")
    hapd.enable()
    ev = dev[0].wait_event(["CTRL-EVENT-BEACON-LOSS"], timeout=10)
    if ev is None:
        raise Exception("Beacon loss not reported")

def test_bgscan_learn_scan_failure(dev, apdev):
    """bgscan_learn and scan failure"""
    hapd = hostapd.add_ap(apdev[0], {"ssid": "bgscan"})

    dev[0].connect("bgscan", key_mgmt="NONE", scan_freq="2412",
                   bgscan="learn:1:-20:2")
    with alloc_fail(dev[0], 1,
                    "wpa_supplicant_trigger_scan;bgscan_learn_timeout"):
        wait_fail_trigger(dev[0], "GET_ALLOC_FAIL")
    ev = dev[0].wait_event(["CTRL-EVENT-SCAN-RESULTS"], 10)
    if ev is None:
        raise Exception("Scanning not continued after failure")

def test_bgscan_learn_oom(dev, apdev):
    """bgscan_learn OOM"""
    hapd = hostapd.add_ap(apdev[0], {"ssid": "bgscan"})

    with alloc_fail(dev[0], 1, "bgscan_learn_init"):
        dev[0].connect("bgscan", key_mgmt="NONE", scan_freq="2412",
                       bgscan="learn:1:-20:2")

def test_bgscan_learn_driver_conf_failure(dev, apdev):
    """bgscan_learn driver configuration failure"""
    hapd = hostapd.add_ap(apdev[0], {"ssid": "bgscan"})

    with fail_test(dev[0], 1, "bgscan_learn_init"):
        dev[0].connect("bgscan", key_mgmt="NONE", scan_freq="2412",
                       bgscan="learn:1:-20:2")

def test_bgscan_unknown_module(dev, apdev):
    """bgscan init failing due to unknown module"""
    hapd = hostapd.add_ap(apdev[0], {"ssid": "bgscan"})
    dev[0].connect("bgscan", key_mgmt="NONE", scan_freq="2412",
                   bgscan="unknown:-20:2")

def test_bgscan_reconfig(dev, apdev):
    """bgscan parameter update"""
    hostapd.add_ap(apdev[0], {"ssid": "bgscan"})
    hostapd.add_ap(apdev[1], {"ssid": "bgscan"})

    id = dev[0].connect("bgscan", key_mgmt="NONE", scan_freq="2412",
                        bgscan="simple:1:-20:2")
    dev[0].set_network_quoted(id, "bgscan", "simple:1:-45:2")
    dev[0].set_network_quoted(id, "bgscan", "learn:1:-20:2")
    dev[0].set_network_quoted(id, "bgscan", "")

def test_bgscan_quiet_good_signal(dev, apdev):
    """bgscan_quiet does not scan while the signal is good"""
    hapd = hostapd.add_ap(apdev[0], {"ssid": "bgscan"})

    dev[0].connect("bgscan", key_mgmt="NONE", scan_freq="2412",
                   bgscan="quiet:1:-80:2")
    ev = dev[0].wait_event(["CTRL-EVENT-SCAN-STARTED"], timeout=5)
    if ev is not None:
        raise Exception("Unexpected scan with a good signal")

def test_bgscan_quiet_weak_signal(dev, apdev):
    """bgscan_quiet scans with back-off while the signal is weak"""
    hapd = hostapd.add_ap(apdev[0], {"ssid": "bgscan"})

    dev[0].connect("bgscan", key_mgmt="NONE", scan_freq="2412",
                   bgscan="quiet:1:-20:4")
    ev = dev[0].wait_event(["CTRL-EVENT-SIGNAL-CHANGE"], timeout=10)
    if ev is None:
        raise Exception("No signal change event")
    if "above=0" not in ev:
        raise Exception("Unexpected signal change event contents: " + ev)

    # Intervals 1, 2, 4, 4 s
    started = []
    for i in range(4):
        ev = dev[0].wait_event(["CTRL-EVENT-SCAN-STARTED"], timeout=10)
        if ev is None:
            raise Exception("Scanning not continued")
        started.append(time.time())
        ev = dev[0].wait_event(["CTRL-EVENT-SCAN-RESULTS"], timeout=5)
        if ev is None:
            raise Exception("Scan did not complete")
    gaps = [b - a for a, b in zip(started, started[1:])]
    logger.info("Scan gaps: " + str(gaps))
    if gaps[0] < 1.5 or gaps[1] < 3.5 or gaps[2] < 3.5 or gaps[2] > 6:
        raise Exception("Unexpected back-off: " + str(gaps))

def test_bgscan_quiet_invalid_params(dev, apdev):
    """bgscan_quiet refuses invalid parameters"""
    hapd = hostapd.add_ap(apdev[0], {"ssid": "bgscan"})

    for p in ["quiet", "quiet:1", "quiet:1:-20", "quiet:1:-20:4:5",
              "quiet:0:-20:4", "quiet:1:-20:0", "quiet:4:-20:1",
              "quiet:1:0:4", "quiet:1:10:4", "quiet:x:-20:4",
              "quiet:1:-20:4x"]:
        dev[0].connect("bgscan", key_mgmt="NONE", scan_freq="2412",
                       bgscan=p)
        ev = dev[0].wait_event(["CTRL-EVENT-SCAN-STARTED"], timeout=1.5)
        if ev is not None:
            raise Exception("bgscan started with invalid parameters " + p)
        dev[0].request("REMOVE_NETWORK all")
        dev[0].wait_disconnected()

def test_bgscan_quiet_beacon_loss(dev, apdev):
    """bgscan_quiet and beacon loss"""
    params = hostapd.wpa2_params(ssid="bgscan", passphrase="12345678")
    params["wpa_key_mgmt"] = "WPA-PSK-SHA256"
    params["ieee80211w"] = "2"
    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].set("disable_sa_query", "1")
    dev[0].connect("bgscan", ieee80211w="2", key_mgmt="WPA-PSK-SHA256",
                   psk="12345678", scan_freq="2412",
                   bgscan="quiet:1:-80:2")
    ev = dev[0].wait_event(["CTRL-EVENT-SIGNAL-CHANGE"], timeout=10)
    if ev is None:
        raise Exception("No signal change event")
    hapd.set("ext_mgmt_frame_handling", "1")
    if "OK" not in hapd.request("STOP_AP"):
        raise Exception("Failed to stop AP")
    hapd.disable()
    hapd.set("ssid", "foo")
    hapd.set("beacon_int", "10000")
    hapd.enable()
    ev = dev[0].wait_event(["CTRL-EVENT-BEACON-LOSS"], timeout=10)
    if ev is None:
        raise Exception("Beacon loss not reported")
    ev = dev[0].wait_event(["CTRL-EVENT-SCAN-STARTED"], timeout=5)
    if ev is None:
        raise Exception("No scan after beacon loss")

def test_bgscan_quiet_scan_failure(dev, apdev):
    """bgscan_quiet and scan failure"""
    hapd = hostapd.add_ap(apdev[0], {"ssid": "bgscan"})

    dev[0].connect("bgscan", key_mgmt="NONE", scan_freq="2412",
                   bgscan="quiet:1:-20:2")
    with alloc_fail(dev[0], 1,
                    "wpa_supplicant_trigger_scan;bgscan_quiet_timeout"):
        wait_fail_trigger(dev[0], "GET_ALLOC_FAIL")
    ev = dev[0].wait_event(["CTRL-EVENT-SCAN-RESULTS"], 10)
    if ev is None:
        raise Exception("Scanning not continued after failure")

def test_bgscan_quiet_oom(dev, apdev):
    """bgscan_quiet OOM"""
    hapd = hostapd.add_ap(apdev[0], {"ssid": "bgscan"})

    with alloc_fail(dev[0], 1, "bgscan_quiet_init"):
        dev[0].connect("bgscan", key_mgmt="NONE", scan_freq="2412",
                       bgscan="quiet:1:-20:2")
