"""Stealth profiles for Kali reconnaissance tooling.

VALEN wraps Kali recon tools (nmap, masscan, ...) so their output feeds the IR
and the attack plan. This module encodes *stealth* as an explicit, configurable
concern: conservative timing, rate limits, randomized host order, inter-probe
jitter, padding, and passive-only modes --- the levers a red team uses to stay
quiet during an authorized engagement.

For authorized engagements only. Every profile requires an explicit target
scope; there is no implicit scanning.
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class StealthProfile:
    name: str = "polite"
    timing: str = "T2"                 # nmap -T0 (paranoid) .. -T5 (insane)
    max_rate: int = 100                # packets/sec; 0 = unlimited
    randomize_hosts: bool = True       # --randomize-hosts
    jitter_ms: tuple = (150, 900)      # random sleep between probe bursts
    data_length: Optional[int] = None  # pad probes to a fixed length
    spoof_mac: Optional[str] = None    # --spoof-mac (OFF by default)
    decoys: Optional[str] = None       # comma list of decoy IPs (OFF by default)
    idle_zombie: Optional[str] = None  # idle/zombie scan -sI (OFF by default)
    host_timeout: Optional[str] = None # --host-timeout
    passive_only: bool = False         # no packets to target (OSINT/DNS only)


PRESETS = {
    "paranoid": StealthProfile(
        name="paranoid", timing="T0", max_rate=3, randomize_hosts=True,
        jitter_ms=(800, 2500), data_length=40, host_timeout="15m"),
    "sneaky": StealthProfile(
        name="sneaky", timing="T2", max_rate=25, randomize_hosts=True,
        jitter_ms=(300, 1200), data_length=32, host_timeout="5m"),
    "polite": StealthProfile(
        name="polite", timing="T2", max_rate=100, randomize_hosts=True,
        jitter_ms=(150, 900), host_timeout="3m"),
    "active": StealthProfile(
        name="active", timing="T4", max_rate=0, randomize_hosts=False,
        jitter_ms=(0, 0)),
}


def build_nmap_args(
    profile: StealthProfile,
    targets: List[str],
    ports: Optional[str] = None,
    extra: Optional[List[str]] = None,
) -> List[str]:
    """Build an nmap command with stealth flags applied."""
    args = ["nmap", "-oX", "-"]  # machine-readable output on stdout
    args += [f"-{profile.timing}"]
    if profile.max_rate:
        args += ["--max-rate", str(profile.max_rate)]
    if profile.randomize_hosts:
        args += ["--randomize-hosts"]
    if profile.data_length:
        args += ["--data-length", str(profile.data_length)]
    if profile.spoof_mac:
        args += ["--spoof-mac", profile.spoof_mac]
    if profile.decoys:
        args += ["-D", profile.decoys]
    if profile.idle_zombie:
        args += ["-sI", profile.idle_zombie]
    if profile.host_timeout:
        args += ["--host-timeout", profile.host_timeout]
    if ports:
        args += ["-p", ports]
    args += list(extra or [])
    args += targets
    return args


def build_masscan_args(
    profile: StealthProfile,
    targets: List[str],
    ports: str,
    extra: Optional[List[str]] = None,
) -> List[str]:
    """Build a masscan command with a bounded rate and JSON output."""
    rate = profile.max_rate or 100
    args = ["masscan", "--rate", str(rate), "-p", ports, "-oJ", "-"]
    args += list(extra or [])
    args += targets
    return args


def jitter_sleep(profile: StealthProfile, rng: Optional[random.Random] = None) -> float:
    """Sleep a randomized interval from the profile's jitter range."""
    lo, hi = profile.jitter_ms
    if hi <= 0:
        return 0.0
    r = rng or random
    delay = r.uniform(lo, hi) / 1000.0
    time.sleep(delay)
    return delay
