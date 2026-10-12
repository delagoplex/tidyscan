# tidyscan

Ordner analysieren und sicher aufräumen. Ein Binary für Windows, macOS und Linux, mit grafischer Oberfläche und Kommandozeile.

**Nichts wird gelöscht.** Alles, was tidyscan aufräumt, wandert in einen Quarantäne-Ordner und lässt sich mit einem Klick oder Befehl zurückholen.

## Funktionen

- **Strukturanalyse**: Ordnerbaum mit Größen, Dateianzahl, Anteil am Gesamtvolumen, Aufteilung nach Kategorie (Bilder, Videos, Dokumente, Installer, …), Altersverteilung und größte Dateien.
- **Alte Dateien**: alles, was seit N Tagen unverändert ist. Zugriffszeiten werden auf Zuverlässigkeit geprüft, weil Windows NTFS und Linux `relatime` sie meist nicht aktualisieren.
- **Duplikate**: byte-identische Dateien über Größe, Präfix-Hash und vollständigen BLAKE3-Hash, parallel auf allen Kernen.
- **Leere Ordner und 0-Byte-Dateien**, rekursiv erkannt.
- **Regeln** in TOML: nach Endung, Glob, Kategorie, Alter und Größe filtern und in Quarantäne oder einen Zielordner (mit `{year}`/`{month}`-Platzhaltern) verschieben.
- **Plan mit Vorschau, Quarantäne und Undo**: Häkchen in der GUI oder Regel-Treffer landen in einem Plan. Beim Ausführen wird jede Bewegung in `undo.json` protokolliert.

## Installation

Voraussetzung ist eine Rust-Toolchain (https://rustup.rs). Unter Linux werden zusätzlich die GTK-Entwicklungspakete für den Dateidialog benötigt:

```bash
sudo apt install libgtk-3-dev libxkbcommon-dev libssl-dev
```

Bauen:

```bash
cargo build --release
```

Das Binary liegt danach unter `target/release/tidyscan` (Windows: `tidyscan.exe`).

## GUI

```bash
tidyscan
tidyscan gui ~/Downloads
```

Links Ordner wählen und scannen. Die Tabs **Übersicht**, **Alte Dateien**, **Duplikate** und **Leere Ordner** zeigen die Ergebnisse. Häkchen setzen füllt den Plan im Tab **Aufräumen**. Dort lassen sich außerdem Regeldateien anwenden, der Plan ausführen und frühere Sitzungen rückgängig machen.

## CLI

```bash
tidyscan scan <pfad> [--top 20] [--json]
tidyscan old <pfad> --days 365 [--use-atime]
tidyscan dupes <pfad> [--min-size 1M]
tidyscan empty <pfad>
tidyscan clean <pfad> --rules rules.toml          # Vorschau
tidyscan clean <pfad> --rules rules.toml --apply  # wirklich verschieben
tidyscan undo --root <pfad>                       # neueste Sitzung zurücknehmen
tidyscan undo <pfad>/.tidyscan-quarantine/<zeitstempel>/undo.json
tidyscan example-rules > rules.toml
```

Alle Scan-Befehle kennen `--skip-hidden`, `--exclude <GLOB>` (mehrfach) und `--max-depth N`.

## Regeln

```toml
[[rule]]
name = "Alte Installer in Quarantäne"
ext = ["exe", "msi", "dmg", "pkg", "deb"]
older_than_days = 90
action = "quarantine"

[[rule]]
name = "Screenshots nach Jahr archivieren"
glob = "**/Screenshot*"
older_than_days = 30
action = "move"
move_to = "Archiv/Screenshots/{year}"
```

Bedingungen: `ext`, `glob` (relativ zum Scan-Ordner, immer mit `/`), `category` (bilder, videos, audio, dokumente, archive, code, installer, disk-images, sonstiges), `older_than_days`, `min_size`, `max_size` (`500`, `10K`, `1.5M`, `2G`). Die erste passende Regel gewinnt. Ein vollständiges Beispiel liegt in [rules.example.toml](rules.example.toml).

## Quarantäne

Verschobene Dateien liegen unter `<Scan-Ordner>/.tidyscan-quarantine/<Zeitstempel>/` mit ihrer ursprünglichen relativen Struktur. Daneben liegt `undo.json`. Ein Undo stellt alles wieder her und überschreibt dabei nie etwas, was inzwischen am Originalpfad liegt. Den Quarantäne-Ordner endgültig zu leeren, bleibt bewusst eine manuelle Entscheidung.

## Grenzen und Hinweise

- Symlinks, Junctions und Cloud-Platzhalter (OneDrive, iCloud "nur online") werden übersprungen und nicht mitgezählt.
- `$RECYCLE.BIN`, `System Volume Information`, `.Trashes`, `.Spotlight-V100` und die Quarantäne selbst werden nie gescannt.
- Zugriffszeiten sind auf den meisten Systemen unzuverlässig. tidyscan prüft das per Stichprobe und fällt auf das Änderungsdatum zurück.
- Inhaltliches Gruppieren ("diese Dateien gehören zusammen") ist noch nicht enthalten.

## Entwicklung

```bash
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt
```

Die Kernlogik liegt in `src/` als Bibliothek (`scan`, `analysis`, `age`, `dupes`, `rules`, `actions`), `cli.rs` und `ui/` sind dünne Schichten darüber.

## Lizenz

MIT
