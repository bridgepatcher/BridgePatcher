# AGENTS.md - rules for AI coding assistants

BridgePatcher is a fork of Dortania's OpenCore Legacy Patcher. AI tools are welcome
here, for brainstorming, debugging and writing code, but the rules below apply to
every change an AI makes or suggests. A human reviews and tests every change before
it lands on `main`.

## 1. Stay close to upstream Dortania

- Match the style of the surrounding code and of upstream OCLP: naming, structure,
  logging, comments, file layout. If upstream solves a similar problem, reuse its
  pattern instead of inventing a new one.
- Don't reformat, rename or reorder code you aren't changing. Unrelated diffs make
  upstream merges harder and hide the real change.
- Areas kept on Dortania's upstream state (GPU, wireless, audio root patches, etc.)
  should only change when you are syncing with upstream or fixing a confirmed bug.

## 2. Don't write WET code

- Search the codebase before adding a helper; extend the existing one if it exists.
- No copy-pasted blocks that differ in one value: use a parameter, a loop or a table
  in `bridgepatcher/datasets`.
- A fix has to reach every place the bug lives, not just the first one you found.

## 3. Keep changes small and explainable

- One topic per commit / PR. No drive-by refactors.
- Don't touch what you weren't asked to touch: CI workflows, licence and credit files,
  branding, release scripts and payloads all need an explicit request.
- Don't add new dependencies without asking.
- Every PR says what changed, why, and how it was tested.

## 4. Correctness over looking finished

- Don't invent APIs, boot-args, kext names, device IDs or macOS behaviour. If you're
  not sure something exists, say so instead of guessing.
- No silent `except: pass`, hard-coded workarounds or stubbed-out code paths that make
  a symptom disappear. A clean GUI on top of hidden bugs is worse than a visible error.
- Root patching, EFI building and secure-boot code can brick or lock a Mac. Flag any
  change there clearly and never claim it works without a hardware test.

## 5. Check before handing over

- Run `python3 .github/scripts/check_python.py --root .` and `ruff check .` on what you changed.
- Say what you tested and what still needs a test on a real T2/T1 Mac. "Untested" is
  an acceptable answer; pretending isn't.
