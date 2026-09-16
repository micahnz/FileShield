# TODO

use notify-send to notify users when an unsafe allowlist hit is matched

add a config item with default to on for unsafe allow list

add the same notifications to allowlist but make the default behaviour off

add the same notifications to denylist and make the default behaviour on

the idea is to at least warn users when an unsafe run was used so they can catch
unexpected access quickly by someone trying to exploit an unsafe rule, the
possible attack vector in the OpenChamber scenario is another process creates
a similar directory and uses a bin called openchamber to access the secret,
whilst the config is readonly for root it is feasible an attacker can guess
a pattern like this is being used and exploit it hence why unsafe_allowlist
should be used with caution, these notes should be added to the readme
