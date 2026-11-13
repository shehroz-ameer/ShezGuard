#!/usr/bin/env bash
# Runs every attack script and prints one summary line per script. EMULATOR ONLY.
cd "$(dirname "$0")"
for s in t1_nested_intent_redirect.sh t2a_sql_injection.sh t2b_webview_url.sh t2c_path_traversal.sh \
         t2d_oversized_extra.sh "t2d_oversized_extra.sh copies" t3_open_redirect.sh t4_link_hijack.sh "t5_malformed_bundle.sh" \
         "t5_malformed_bundle.sh gadget" t6_encoding_manual_check.sh; do
    out=$(bash $s 2>&1)
    printf '%-36s %s\n' "$s" "$(echo "$out" | grep '^RESULT:' | tail -1)"
done
