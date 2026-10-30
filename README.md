Simutronic's [Wrayth](https://www.play.net/dr/play/wrayth/notes.asp) front-end has at least 2 leaks that can cause it to crash regularly.
## #1: Leaky Pens ##
This issue is most likely to crash a session first. Every time you prepare a spell or move an item in your hands, Wrayth updates the hand display slots (left hand, right hand, or spell hand) to show the item or spell name. It uses the Windows graphics system (GDI) to call a CreatePen function to update the hands window, but it never runs DeleteObject. The non-deleted pen GDI objects pile up. The default Windows limit is 10,000 GDI objects per process. So if you juggle enough items and prepare enough spells, your GDI count will hit 10,000, Windows won't allow any new objects for Wrayth, and it will crash. 

This can be corrected with a patch. However, anyone who doesn't want to run a non-stock Wrayth.exe can increase Windows' limit on GDI objects above the default 10,000 (by changing `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\GDIProcessHandleQuota` in Regedit) to extend runtime before crashing. The max possible is 65,536. This is easy and low impact, [although there are theoretical downsides to increasing the GDI limit on Windows.](<https://devblogs.microsoft.com/oldnewthing/20210831-00/?p=105624/>) You must reboot after editing the registry value. Merely increasing this limit to 20,000 will likely double Wrayth's lifespan (~24 hours) under typical gameplay conditions before a separate crash occurs.
## #2: Zombie progressBars ##
The second issue comes from the progressBar UI elements (health, mana, fatigue, spirit, and concentration). Any update rebuilds the bar's components (background, colored bar, label, etc.), but the old components are never freed. Each update grows Wrayth's memory footprint, until it crashes at 2 GB.

## Patching the Leaks ##
Backup your original Wrayth.exe (default location: `C:\Program Files (x86)\SIMU\Wrayth\Wrayth.exe`). Replace the original Wrayth.exe with your patched exe (which you rename to Wrayth.exe). You can either download a patched exe here, or generate your own using `patch_wrayth.py`.

`python patch_wrayth.py Wrayth.exe Wrayth_patched.exe`

```
patch_wrayth.py required positional arguments:
  src                original Wrayth.exe (version 1.0.1.28, SHA-256 is checked)
  dst                output file (eg, Wrayth_patched.exe)

optional arguments:
  --dry              run every check, write nothing
  --no-gdi           skip the leaky-pen fix
  --no-leak          skip the progressBar fix
  --no-laa           do not set the LARGEADDRESSAWARE flag (which increases the memory limit from 2GB to 4GB)
```

## Testing Leaking ##
The `\testing\wraythmon.ps1` powershell script monitors Wrayth's resource usage. It displays a summary and writes the results to wrayth-counters.csv

`\testing\stress_test.lic` is a Lich script that attempts to cause both types of leaks as rapidly as possible. (It can cause a leaky pen crash in ~30 minutes and a progressBar crash in ~90 minutes.)
