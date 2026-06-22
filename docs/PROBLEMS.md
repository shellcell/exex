# PROBLEMS / BUGS / ISSUES

_No known open issues._

## Fixed

- **Fat Mach-O arch switching (e.g. `/usr/bin/sqlite3`).** Slices sharing a CPU
  type collapsed to one name (`x86_64` for both x86_64 and x86_64h; `arm64` for
  arm64e), so they showed as duplicates and `t` could not cycle to / select them.
  Fixed by naming slices with their CPU subtype (`machoArchName`): x86_64 /
  x86_64h / arm64 / arm64e are now distinct and individually selectable.
