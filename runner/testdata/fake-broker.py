"""Stand-in for the broker in runner tests: its command line contains 'target/debug/broker' so
the runner finds it. On SIGUSR1 (the kill switch) it records that and exits, unless told to ignore it."""
import os, signal, sys, time

ignore = os.environ.get("FAKE_IGNORE_KILL") == "1"


def on_usr1(*_):
    open("fake-broker-killed", "w").write("SIGUSR1")
    if not ignore:
        sys.exit(0)


signal.signal(signal.SIGUSR1, on_usr1)
while True:
    time.sleep(0.1)