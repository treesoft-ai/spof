#!/usr/bin/env python3
"""Spof — AI pentesting harness entrypoint."""

import argparse
from src import slate
from src import chat


def main():
    parser = argparse.ArgumentParser(
        description="Spof — AI Pentesting Harness",
        add_help=False,
    )
    parser.add_argument("--help", action="store_true", help="Show help and exit")
    parser.add_argument("--provider", choices=["anthropic", "openrouter", "agentrouter", "hackclub"], default=None, help="Force a specific AI provider")
    parser.add_argument("--model", type=str, default=None, help="Force a specific LLM model ID")
    parser.add_argument("--description-less", "--dl", action="store_true", help="Omit tool descriptions from system prompt and schemas to reduce AI skepticism")
    parser.add_argument("--no-tools", "--nt", action="store_true", help="Remove all tools — pure chatbot interface with no tool verification")
    parser.add_argument("--temperature", "--temp", type=float, default=None, help="LLM sampling temperature (defaults to 0.0 for benchmark, or provider default for chat)")
    parser.add_argument("--benchmark", type=str, nargs="?", const="all", default=None,
                        metavar="TIERS",
                        help="Run Spof Check v1 benchmark [low,medium,high,critical,all,L5]")
    parser.add_argument("command", nargs="?", default=None, help="chat, help")

    opts, _ = parser.parse_known_args()

    if opts.help or opts.command == "help":
        slate.slate_help()
        return

    if opts.benchmark is not None:
        from src.benchmark import run_benchmark
        run_benchmark(
            opts.benchmark,
            provider=opts.provider,
            model=opts.model,
            description_less=opts.description_less,
            temperature=opts.temperature,
        )
        return


    chat.cmd_chat(opts)



if __name__ == "__main__":
    main()
