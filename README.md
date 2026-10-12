# Nessus Report Lens

Ein lokales, statisches Lesezeichen-Hub-Modul zum Prüfen von Nessus-HTML-Berichten. Es listet die im Abschnitt **Vulnerabilities by Host** gefundenen Hosts/Domains auf und zeigt pro Eintrag Critical-, High- und Medium-Zähler sowie die zugehörigen Plugin-Namen. Critical und High werden in der Sortierung und im Schnellfilter priorisiert; Medium bleibt in Übersicht und Details sichtbar.

## Verwendung

- Den Ordner `nessus_report_parser` im Lesezeichen-Hub über **Hinzufügen → Lokales Modul** einbinden oder [index.html](index.html) direkt im Browser öffnen.
- Einen Nessus-HTML-Export per Drag & Drop ablegen oder über **HTML-Datei auswählen** laden.
- Domains durchsuchen, auf Critical/High filtern und **Details** öffnen, um die gemeldeten Plugin-Findings zu sehen.

Der Bericht wird ausschließlich im Browser verarbeitet und nicht hochgeladen oder gespeichert. Unterstützt werden Nessus-HTML-Exporte mit dem Abschnitt `Vulnerabilities by Host`; maximal 50 MB.

## Dateien

- [index.html](index.html): Oberfläche und Upload-Bereich
- [app.js](app.js): HTML-Parsing, Auswertung und Such-/Filterfunktionen
- [styles.css](styles.css): responsives Dark-UI
- `wab_nessus_report.html`: Referenzbericht zum Testen; wird nicht automatisch eingelesen
