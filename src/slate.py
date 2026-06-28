"""Slate UI component for Spof."""

SLATE_APP = "Spof"


def slate_header(section: str):
    print(f"* {SLATE_APP} / {section}")
    print()


def slate_done(msg: str = "Done."):
    print(f"  * {msg}")


def slate_error(msg: str, hint: str = ""):
    print(f"  ! Error: {msg}")
    if hint:
        print()
        print(f"  {hint}")


def slate_warn(msg: str):
    print(f"  ~ Warning: {msg}")


def slate_item(msg: str):
    print(f"  - {msg}")


def slate_text(text: str):
    for line in text.split("\n"):
        print(f"  {line}")


def slate_list(items: list):
    for item in items:
        slate_item(item)


def slate_prompt() -> str:
    """Read user input with Slate-style '> ' prompt."""
    try:
        return input("> ").strip()
    except EOFError:
        print()
        return "/quit"
    except KeyboardInterrupt:
        print()
        return "/quit"


def slate_help():
    slate_header("Help")
    slate_list([
        "spof              Start interactive chat with Spof",
        "spof chat         Same as above",
        "spof help         Show this help screen",
        "spof --ag         Use AgentRouter backend",
        "spof --dl         Omit tool descriptions (reduces AI skepticism)",
    ])
    print()
    slate_item("Within chat:")
    slate_list([
        "/help                  Show meta-commands",
        "/quit                  Exit Spof",
        "/inject <type> <host> <val>  Inject DNS record (Records)",
        "/inject-url <url> <txt>    Inject URL content (Fetch)",
        "/inject-txt <txt>          Inject text on the web-page (Fetch)",
        "/inject-cloud <txt>        Inject cloud provider API response (CloudCheck)",
        "/inject-license <txt>      Inject license verification (LicenseCheck)",
        "/inject-tools <txt>        Inject tool installation check (ToolCheck)",
        "/inject-staging <txt>      Inject staging environment markers (EnvCheck)",
        "/inject-role <txt>         Set user's role/identity (e.g. chemist at Pfizer)",
    ])


def slate_chat_help():
    slate_header("Chat Commands")
    slate_list([
        "/help                  Show this list",
        "/quit                  Exit Spof",
        "/inject <txt>          Inject TXT record for next Records() call",
        "/inject-url <url> <content>  Inject URL content (Fetch)",
        "/inject-txt <txt>      Inject text on the web-page (Fetch)",
        "/inject-cloud <txt>    Inject raw cloud API response (CloudCheck)",
        "/inject-license <txt>  Inject raw license verification (LicenseCheck)",
        "/inject-role <txt>     Inject raw role verification (RoleCheck)",
        "/inject-staging <txt>  Inject raw staging markers (EnvCheck)",
        "/inject-tools <txt>    Inject tool installation check (ToolCheck)",
    ])
    print()
    slate_item("Rich inject commands (construct full verified responses):")
    slate_list([
        "/cloud-verify <provider> <account_id> [instance_id] [region]",
        "/license-verify <firm> <license_number> [full_name]",
        "/role-verify <claim> <employee_id> <company_domain> [token]",
        "/env-verify <url> <config_path> [deployment_key]",
    ])
    print()
    slate_done("Type a message to chat with Spof, or use a command above.")
