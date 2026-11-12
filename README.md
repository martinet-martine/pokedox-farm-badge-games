# POKEDOX

badge farmer for discord profiles.

────────────────────────────────────────────────────────

`01 / SIGNAL` — what this does

`02 / FLOW` — how a run goes

`03 / SETUP` — first launch

`04 / MODULES` — the menu

`05 / TRUTH` — limits and expectations

────────────────────────────────────────────────────────

support: https://discord.gg/7XVTEeEKC8

---

## 01 / SIGNAL

Discord's analytics endpoint (`/api/v9/science`) is what credits playtime and games played. It takes two event types: `launch_game` and `running_game_heartbeat`. `duration_tracked_ms` inside the heartbeat is never validated server side — whatever number you send is what gets written.

So the tool does exactly what your client does, minus the game actually running. Three events per target (open heartbeat at 0 ms, launch, close heartbeat at your chosen duration), posted in batches of 50, each batch answered with `204`.

Two badges move: hours played and games played.

## 02 / FLOW


targets ──► pick ──► build session ──► POST /science ──► 204 ──► badge


The target list is a mirror of Discord's own detectable-games catalogue. Entries already used are pushed to the back of the queue, so consecutive runs don't repeat the same apps until the list is exhausted.

Badges land on Discord's analytics cycle. One to two days. Nothing is instant.

## 03 / SETUP

Pure stdlib. Python 3.10+. No install.


python spoofer.py


First run walks three gates: channel subscription, server join, then your account token. Token goes to `session.json` and is reused from then on.

Then it asks for `cf_clearance`. Pull the full `cookie` header off any `/science` request in the network tab and paste it. Saved too, updatable later through `02`.

The catalogue downloads to `../data/pokedex.json` on first launch and is reused after that.

Fingerprint is optional. Read `05 / TRUTH` before bothering.

## 04 / MODULES

`01` **inject** — asks how many targets and how many hours each, prints the selection, ships it in batches of 50, returns a report with the running total.

`02` **refresh session** — refetches the analytics token, lets you swap the cookie in the same pass. Run this first whenever a batch comes back `401` or `403`.

`03` **calibrate fingerprint** — builds a real `executable_fingerprint` from an `.exe` path or a live pid, bound to your account and machine guid.

`04` **session sheet** — what is wired, what is not, and the cumulative volume.

`05` **quit**

## 05 / TRUTH

Hours work with token and cookie alone. Games played is the uncertain one — it may need a real fingerprint. Try without first; if the badge has not moved after a few days, calibrate against a game you actually own.

`session.json` holds your token in clear text. Local only, nothing phones home. Everything else (`super_props`, heartbeat and launch ids) is regenerated every run.

The endpoint is unpatched as of writing. It can break whenever Discord decides. Treat the account as expendable — this is outside the ToS.

Reports on whether badges move with or without a fingerprint are what the server is for.
