# Troubleshooting

- **No popups appear?** The daemon auto-detects the Wayland socket and D-Bus address under `/run/user/<uid>/`. Verify the desktop session is active and `kdialog` is installed. If kdialog is missing or fails, access is denied (fail closed).

- **Dialog does not match your theme?** The daemon forwards a whitelist of your session's appearance variables (`XDG_CURRENT_DESKTOP`, `KDE_FULL_SESSION`/`KDE_SESSION_VERSION`, `QT_QPA_PLATFORMTHEME`, `QT_STYLE_OVERRIDE`, scale factors, locale, cursor) into the dialog child after dropping to your user. On Plasma/KDE this makes kdialog use your color scheme and fonts automatically. On other desktops a Qt platform theme integration is needed (e.g. `qgnomeplatform`/adwaita-qt for GNOME, `qt6ct`); without one Qt falls back to its default light theme.

- **Dialog behavior on failure**: the access prompt is a `kdialog --menu`; the decision is the selected row's tag on stdout with a zero exit code. Cancel, window close, the 30 s timeout, exec failures and every kdialog runtime error produce no selection and **deny** (fail closed). The hash-change prompt uses the same mechanism with two rows (**Update & Allow**, **Deny** preselected): only Update & Allow on stdout with exit 0 updates the pin.

- **Access blocked for a trusted process?** Add it to `[allowlist]` in `/etc/fileshield.conf` and reload. If already allowlisted, the prompt may be about a hash change — approve only if you expected the binary update. If the binary cannot be pinned (AppImage, tmp-mount tool), use `[unsafe_allowlist]`. Check `journalctl -u fileshield -n 20`.

- **Daemon fails to start?** Confirm root — `fanotify_init` requires `CAP_SYS_ADMIN`. Check `journalctl -u fileshield -p err`.

- **Path watched but events not firing?** Verify the mark was added (`journalctl -t fileshield | grep "mark added"`). Paths on NFS/CIFS or inside containers are not supported by fanotify.

- **All accesses denied with no popup on headless machine?** Fileshield requires a live desktop session for dialogs. On headless hosts unknown accesses are denied (fail-closed). Run in foreground mode and inspect stderr.
