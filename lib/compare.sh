# shellcheck shell=bash
# DOXA scan comparison: previous scan vs current scan, matched by finding fingerprint
# (sha256 of title + URL + category), so reports stay comparable between runs.
shopt -u patsub_replacement 2>/dev/null || true

COMPARE_SPEC="" COMPARE_DIR="" COMPARE_ERROR="" COMPARE_DONE=0
CMP_NEW=0 CMP_RESOLVED=0 CMP_PERSISTENT=0 CMP_CHANGED=0 CMP_NOTRETESTED=0
CMP_FILE=""

scan_meta_write() { # called once at start
  {
    printf 'doxa_version=%s\n' "$DOXA_VERSION"
    printf 'target=%s\nhost=%s\nport=%s\nmode=%s\nstarted=%s\n' "$TARGET_URL" "$HOST" "${PORT:-default}" "$MODE" "$START_ISO"
  } >"$LOG_DIR/scan_meta.txt"
}

compare_meta_get() { sed -nE "s/^$2=(.*)$/\1/p" "$1/logs/scan_meta.txt" 2>/dev/null | head -1; }

# compare_resolve -> COMPARE_DIR (or COMPARE_ERROR)
compare_resolve() {
  COMPARE_DIR=""; COMPARE_ERROR=""
  local spec=$COMPARE_SPEC cur safe d best=""
  if [[ $spec == auto ]]; then
    cur=$(basename "$OUTDIR")
    safe=${HOST//[^A-Za-z0-9._-]/_}; [[ -n $PORT ]] && safe+="_$PORT"
    for d in "$OUTPUT_ROOT"/"${safe}"_*; do
      [[ -d $d && -s $d/logs/findings.final.tsv ]] || continue
      [[ $(basename "$d") < "$cur" ]] && best=$d
    done
    [[ -n $best ]] || { COMPARE_ERROR="no earlier scan of $HOST found under $OUTPUT_ROOT"; return 1; }
    COMPARE_DIR=$best
  else
    [[ -d $spec ]] || { COMPARE_ERROR="previous report directory not found: $spec"; return 1; }
    [[ -f $spec/logs/findings.final.tsv ]] || { COMPARE_ERROR="not a DOXA v2 report directory (missing logs/findings.final.tsv): $spec"; return 1; }
    COMPARE_DIR=$(cd "$spec" && pwd)
  fi
  local ph; ph=$(compare_meta_get "$COMPARE_DIR" host)
  if [[ -n $ph && $ph != "$HOST" ]]; then COMPARE_ERROR="previous scan was for host '$ph', current host is '$HOST'"; COMPARE_DIR=""; return 1; fi
  return 0
}

# compare_scans: writes logs/comparison.tsv: STATUS id severity previous_severity title url module
compare_scans() {
  COMPARE_DONE=0; CMP_NEW=0; CMP_RESOLVED=0; CMP_PERSISTENT=0; CMP_CHANGED=0; CMP_NOTRETESTED=0
  CMP_FILE="$LOG_DIR/comparison.tsv"; : >"$CMP_FILE"
  [[ -n $COMPARE_SPEC ]] || return 0
  if ! compare_resolve; then LIMITS+=("Scan comparison was requested but is unavailable: $COMPARE_ERROR"); warn "Comparison unavailable: $COMPARE_ERROR"; return 1; fi
  local -A prev_sev=() prev_title=() prev_url=() prev_mod=() prev_id=() cur_seen=() cur_ok=()
  local id fp sev title url cat status conf module rest m st
  while IFS=$'\037' read -r id fp sev title url cat status conf module rest; do
    prev_sev[$fp]=$sev; prev_title[$fp]=$title; prev_url[$fp]=$url; prev_mod[$fp]=$module; prev_id[$fp]=$id
  done <"$COMPARE_DIR/logs/findings.final.tsv"
  while IFS=$'\t' read -r m st rest; do [[ $st == OK ]] && cur_ok[$m]=1; done <"$MODULES_TSV"
  while IFS=$'\037' read -r id fp sev title url cat status conf module rest; do
    cur_seen[$fp]=1
    if [[ -z ${prev_sev[$fp]:-} ]]; then
      printf 'NEW\t%s\t%s\t-\t%s\t%s\t%s\n' "$id" "$sev" "$title" "$url" "$module" >>"$CMP_FILE"; CMP_NEW=$((CMP_NEW + 1))
    elif [[ ${prev_sev[$fp]} != "$sev" ]]; then
      printf 'CHANGED\t%s\t%s\t%s\t%s\t%s\t%s\n' "$id" "$sev" "${prev_sev[$fp]}" "$title" "$url" "$module" >>"$CMP_FILE"; CMP_CHANGED=$((CMP_CHANGED + 1))
    else
      printf 'PERSISTENT\t%s\t%s\t%s\t%s\t%s\t%s\n' "$id" "$sev" "$sev" "$title" "$url" "$module" >>"$CMP_FILE"; CMP_PERSISTENT=$((CMP_PERSISTENT + 1))
    fi
  done <"$FINAL_TSV"
  for fp in "${!prev_sev[@]}"; do
    [[ -n ${cur_seen[$fp]:-} ]] && continue
    # a finding only counts as resolved when the module that produced it ran successfully this time
    if [[ -n ${cur_ok[${prev_mod[$fp]}]:-} ]]; then
      printf 'RESOLVED\t%s\t-\t%s\t%s\t%s\t%s\n' "${prev_id[$fp]}" "${prev_sev[$fp]}" "${prev_title[$fp]}" "${prev_url[$fp]}" "${prev_mod[$fp]}" >>"$CMP_FILE"; CMP_RESOLVED=$((CMP_RESOLVED + 1))
    else
      printf 'NOT_RETESTED\t%s\t-\t%s\t%s\t%s\t%s\n' "${prev_id[$fp]}" "${prev_sev[$fp]}" "${prev_title[$fp]}" "${prev_url[$fp]}" "${prev_mod[$fp]}" >>"$CMP_FILE"; CMP_NOTRETESTED=$((CMP_NOTRETESTED + 1))
    fi
  done
  LC_ALL=C sort -t $'\t' -k1,1 -k3,3 -s "$CMP_FILE" -o "$CMP_FILE"
  COMPARE_DONE=1
  return 0
}
