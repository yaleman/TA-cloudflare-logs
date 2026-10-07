"""Entry point for the dedicated local Splunk install and live-test workflow."""

from scripts.live_testing import cli

if __name__ == "__main__":
    raise SystemExit(cli())
