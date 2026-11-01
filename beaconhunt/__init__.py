"""beaconhunt - detect C2 beaconing in connection logs."""

from .core import BeaconScore, Connection, analyse, group_connections, score_group

__version__ = "0.1.0"
__all__ = ["Connection", "BeaconScore", "analyse", "score_group", "group_connections"]
