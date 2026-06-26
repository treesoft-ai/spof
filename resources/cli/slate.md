# TreeSoft Slate

Monochrome. Minimalist. No borders. No full caps.

---

## 1. Core Principles

- **Monochrome** — no ANSI color. Output must read identically on any terminal.
- **Minimalist** — plain text only. No box-drawing, no ASCII frames.
- **Title Case, never FULL CAPS** — `Error`, not `ERROR`. `Status`, not `STATUS`.
- **Symbols over color** — meaning is carried by prefix symbols, not color codes.
- **Breadcrumb identity** — every screen states App / Section.
- **Containment** — external output (e.g., library warnings) that does not match Slate must be intercepted and hidden, replaced with Slate-compliant equivalent formats.

---

## 2. Layout Structure

### Header (always first line of output)
```
* {AppName} / {Section}
```
- `*` marks the app identity line — always present, always first.
- `{Section}` updates per command (`Help`, `Steer`, `Domains`, `Config`...).
- One blank line after the header, before content.

### Body
- Indented 2 spaces under the header.
- No nested boxes. Use indentation + blank lines to group, not lines/borders.

---

## 3. Status Symbols

No color — symbols carry meaning instead.

| Symbol | Meaning  | Example |
|--------|----------|---------|
| `*`    | Identity / success | `* Done.` |
| `!`    | Error    | `! Error: Domain not found.` |
| `~`    | Warning  | `~ Warning: Config is using defaults.` |
| `?`    | Prompt / confirmation | `? Overwrite existing config? (y/n)` |
| `>`    | Input cursor | `> ` |
| `-`    | List item | `- init` |

Keep this set fixed across every TreeSoft CLI. A user who learns it once should never relearn it in another tool.

---

## 4. Progress (Basic Only)

No spinners, no bars. Plain percentage or step count, overwritten in place.

```
Loading domain vectors... 100%
Applying steering...       64%
```

For unknown-length tasks, use step counts instead of a percent:

```
Running benchmark... step 3/12
```

---

## 5. Prompts & Input

```
> 
```
Plain `>` with a trailing space. Confirmations use `?`:
```
? Overwrite existing config? (y/n) 
```

---

## 6. Lists & Tables

No rich tables — aligned plain text, two-space minimum gutter.

```
* Rouve / Domains

  Name        Layers   Status
  medical     12       Active
  legal       8        Inactive
  finance     12       Active
```

Command lists (e.g. help screens) use `-` or left-aligned name + description:

```
* Rouve / Help

  Commands

  init        Initialize a new domain config
  steer       Apply activation steering to a prompt
  bench       Run benchmark suite
  status      Show current session state

  Run 'rouve <command> --help' for details on a command.
```

---

## 7. Errors & Warnings

```
* Rouve / Steer

  ! Error: Domain "medical" not found.

  Run 'rouve domains' to list available domains.
```

```
* Rouve / Config

  ~ Warning: No config file found. Using defaults.
```

Errors and warnings always: state what happened in one line, then offer the next action on the line below (blank line between).

### Intercepting External Output

Any diagnostic output, warning, or log message from third-party libraries (e.g., HuggingFace warnings) that does not match the Slate format must be intercepted and hidden from the terminal. If the warning or message needs to be communicated, it must be rewritten and replaced with a Slate-matching equivalent (e.g., using `~` or `!`).

---

## 8. Success Output

```
* Rouve / Steer

  Steering applied. 3 layers modified.

  Output saved to ./out/steered_response.txt
```

No `[OK]` tags, no checkmarks — the `*` header already signals success unless `!` or `~` appears.

---

## 9. Full Reference Example

```
C:/> uv run main.py steer --domain medical

* Rouve / Steer

  Loading domain vectors... 100%
  Applying steering...      100%

  Steering applied. 3 layers modified.

  Output saved to ./out/steered_response.txt
```

---

## 10. Rules Summary (quick reference)

1. Header is always `* {AppName} / {Section}`.
2. No color, no borders, no FULL CAPS.
3. Status carried by `*` `!` `~` `?` only.
4. Progress is plain `%` or `step x/y`, no animation.
5. Tables are aligned plain text, 2-space gutter minimum.
6. One blank line between header/body/footer blocks.