# Contributing to BridgePatcher

Thanks for helping out! A few ground rules keep the codebase healthy and easy to
merge with upstream Dortania OpenCore Legacy Patcher.

## Code style

- Follow the coding style of upstream Dortania and the code around your change.
- But keep BridgePatcher's own names: no upstream app names, bundle IDs, NVRAM keys
  or folders (see `.github/scripts/branding_check.py`).
- Avoid duplicated (WET) code; reuse or extend existing helpers.
- Keep PRs small and focused on one topic.

## Using AI

AI tools are allowed, for ideas, debugging and code. The rules are about review, not
about who typed the code:

- **You own what you submit.** Read and understand every line, even if an AI wrote it.
- **Tested on real hardware** before merging, wherever the change affects patching,
  booting or the EFI. Say which Mac and macOS version you tested on.
- **AI tools must follow [AGENTS.md](AGENTS.md)**: most assistants read it
  automatically.
- **Every PR gets a human review** before it lands on `main`.

## Pull requests

Describe what changed, why, and how you tested it. Mark untested parts clearly.
