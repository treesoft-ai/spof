#!/usr/bin/env python3
"""Spof — AI pentesting harness entrypoint."""

import argparse
from src import config
from src import slate
from src import chat


def main():
    parser = argparse.ArgumentParser(
        description="Spof — AI Pentesting Harness",
        add_help=False,
    )
    parser.add_argument("--help", action="store_true", help="Show help and exit")
    parser.add_argument("--version", action="store_true", help="Show version and exit")
    parser.add_argument("--provider", choices=["anthropic", "openrouter", "agentrouter", "hackclub"], default=None, help="Force a specific AI provider")
    parser.add_argument("--model", type=str, default=None, help="Force a specific LLM model ID")
    parser.add_argument("command", nargs="?", default=None, help="chat, help")

    opts, _ = parser.parse_known_args()

    if opts.version:
        slate.slate_version()
        return

    if opts.help or opts.command == "help":
        slate.slate_help()
        return

    chat.cmd_chat(opts)


if __name__ == "__main__":
    main()
