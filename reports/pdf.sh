# shellcheck shell=bash
# DOXA PDF report (report.pdf): rendered from report.html with whichever PDF tool is installed.
# Supported: chromium / google-chrome (headless), wkhtmltopdf, weasyprint. Skipped, with a recorded
# limitation, when none is available; a failed render is logged and warned, never silent.
shopt -u patsub_replacement 2>/dev/null || true

NO_PDF=${NO_PDF:-0}
PDF_TOOL="" PDF_STATUS=""

pdf_tool_detect() {
  PDF_TOOL=""
  local t
  (( NO_PDF )) && { PDF_STATUS="disabled (--no-pdf)"; return 0; }
  for t in chromium chromium-browser google-chrome google-chrome-stable wkhtmltopdf weasyprint; do
    if have "$t"; then PDF_TOOL=$t; break; fi
  done
  if [[ -z $PDF_TOOL ]]; then
    PDF_STATUS="skipped: no PDF tool installed (install chromium, wkhtmltopdf or weasyprint)"
    LIMITS+=("PDF report was not generated: no PDF tool is installed (chromium, wkhtmltopdf or weasyprint).")
  fi
  return 0
}

pdf_valid() { [[ -s $1 && $(head -c 5 "$1" 2>/dev/null) == "%PDF-" ]]; }

generate_pdf_report() {
  local html="$OUTDIR/report.html" pdf="$OUTDIR/report.pdf" rc=0
  [[ -n $PDF_TOOL ]] || return 0
  [[ -s $html ]] || { PDF_STATUS="failed: report.html missing"; return 1; }
  rm -f "$pdf"
  case $PDF_TOOL in
    chromium|chromium-browser|google-chrome|google-chrome-stable)
      run_tool pdf 120 "$LOG_DIR/pdf.log" "$PDF_TOOL" --headless --no-sandbox --disable-gpu --no-pdf-header-footer \
        --print-to-pdf="$pdf" "file://$html" || rc=$? ;;
    wkhtmltopdf)
      run_tool pdf 120 "$LOG_DIR/pdf.log" wkhtmltopdf --quiet --enable-local-file-access --page-size A4 "$html" "$pdf" || rc=$?
      if ! pdf_valid "$pdf"; then
        rc=0; run_tool pdf-retry 120 "$LOG_DIR/pdf.log" wkhtmltopdf --quiet --page-size A4 "$html" "$pdf" || rc=$?
      fi ;;
    weasyprint)
      run_tool pdf 120 "$LOG_DIR/pdf.log" weasyprint "$html" "$pdf" || rc=$? ;;
  esac
  if pdf_valid "$pdf"; then
    PDF_STATUS="generated with $PDF_TOOL"
    return 0
  fi
  rm -f "$pdf"
  PDF_STATUS="failed: $PDF_TOOL exit $rc, no valid PDF produced (see logs/pdf.log)"
  warn "PDF generation failed: $PDF_STATUS"
  LIMITS+=("PDF report generation failed with $PDF_TOOL (see logs/pdf.log).")
  return 1
}
