# shellcheck shell=bash
# DOXA module: evidence (ported from v1.0.0, hardened for v2.0)
shopt -u patsub_replacement 2>/dev/null || true

collect_evidence() {
  local shot="$OUTDIR/screenshots/homepage.png" tool="" rc=0 t
  for t in chromium chromium-browser google-chrome gowitness; do have "$t" && { tool=$t; break; }; done
  cp "$ROOT_BODY" "$OUTDIR/logs/homepage_body.html" 2>/dev/null
  if [[ -z $tool ]]; then
    MODULE_STATUS=SKIPPED; MODULE_DETAIL="no screenshot tool (install chromium); headers and page body archived"
    LIMITS+=("No screenshots were captured (no headless browser found).")
    return 0
  fi
  if [[ $tool == gowitness ]]; then
    run_tool gowitness 90 "$LOG_DIR/screenshot.log" gowitness single --screenshot-path "$OUTDIR/screenshots" "$SCAN_BASE/" || rc=$?
  else
    run_tool "$tool" 90 "$LOG_DIR/screenshot.log" "$tool" --headless --no-sandbox --disable-gpu --ignore-certificate-errors --hide-scrollbars \
      --window-size=1366,768 --screenshot="$shot" "$SCAN_BASE/" || rc=$?
  fi
  if compgen -G "$OUTDIR/screenshots/*.png" >/dev/null; then MODULE_DETAIL="screenshot captured with $tool"; return 0; fi
  MODULE_DETAIL="$tool produced no screenshot (exit $rc)"; return 1
}
