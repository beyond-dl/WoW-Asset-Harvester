# WoW Asset Harvester

A small helper for people who make custom World of Warcraft maps (WotLK 3.3.5a) in Noggit.  
It saves you from manually hunting down every model, texture, and DBC entry your map needs.

## What it does

- Reads your `.adt` files and the relevant DBCs.
- Looks through a folder of custom/retroported files you point it to.
- Copies everything that is actually referenced: M2, .skin, .blp, WMO, and other assets that are visible on the ADT or listed in the DBC.
- Puts them into an output folder so you can build a new patch.

It does **not** try to be perfect. It just automates the boring part of finding files.

## How it works

The ADT is the main source of truth. The script scans your map tiles for ground effect IDs and other references. If it finds them, it pulls only the matching DBC entries (precise mode).

If no ground effect IDs are found on the ADT (some maps don't store them, or they're stored elsewhere), the script switches to fallback mode. In that case it copies **every custom DBC entry** (any row above the threshold) so nothing your map might use is left behind. This is safe but less selective.

## How to use

1. Make sure Python is installed.
2. Double-click `WoWAssetHarvester 1.4.3.py`.

A window will open. Fill in:
- **Source folder** – where your extracted/custom assets live.
- **ADT folder** – your map tiles.
- **DBC folder** – the DBC files you want to use.
- **Output folder** – where the collected files go.

Then let it run.

## DBC thresholds

The script uses ID thresholds to tell stock 3.3.5a data from your custom entries. Defaults:
- GroundEffectDoodad: 798
- GroundEffectTexture: 72973
- LightSkybox: 148

Rows with IDs **above** these values are treated as custom and will always be copied. Rows below are skipped if missing from your source (the game client already has them).

## Output files

After running, you get:
- `harvest_found.txt` – everything that was found and copied.
- `harvest_missing.txt` – files referenced but not present in your source.
- `harvest_tree.txt` – a rough log of what was parsed.
- `harvest_found_dbc.txt` – short DBC-related report and a list of model path bugs (like `.bl` instead of `.blp`).

## License

MIT. Do whatever you want with it.
