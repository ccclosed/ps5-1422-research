# Пробы p55x / v9xx (скачаны из TFujiwara/PS5-14.10-Research, ветка research/tfujiwara-v919-v929-campaign)

| Файл | Размер | sha256 (16) | Что это |
|---|---|---|---|
| `p550-canvas-uaf-transform-leak.js` | 7690 | `087c72f993dc9a5c` | PROBE p550: Canvas getContext() UAF — getTransform() channel verification |
| `p551-canvas-uaf-variants.js` | 7763 | `21cbbba6f24cbff6` | PROBE p551: Canvas getContext() UAF — trigger variant sweep |
| `p552-canvas-uaf-desync-exploit.js` | 9813 | `90430449c4657148` | PROBE p552: Canvas UAF exploit chain via desynchronized getter |
| `p553-canvas-uaf-write-confirm.js` | 7881 | `ab6dcd23585d85cc` | PROBE p553: Canvas UAF write primitive confirmation |
| `p554-canvas-uaf-crosstype-offsetmap.js` | 12161 | `22b6858de54d4789` | PROBE p554: Cross-type reclaim + offset mapping |
| `p554b-crosstype-lean.js` | 6823 | `19396d11c63538ac` | PROBE p554b: Ultra-lean cross-type reclaim test |
| `p554c-crosstype-safe.js` | 3533 | `a6ca35a22377491b` | PROBE p554c: Cross-type reclaim — NO pre-spray read |
| `p554d-sametype-deep.js` | 7516 | `7a715036d0a9f537` | PROBE p554d: Same-type alias deep mapping |
| `p555-reentrancy-timing.js` | 20401 | `8e049b4e6811233a` | PROBE p555: Canvas2D reentrancy timing + state stack realloc oracle |
| `p556-rab-offset-race.js` | 21226 | `d2137a5f8d131cbf` | PROBE p556: RAB offset validation race + alternative TypedArray OOB paths |
| `p558-rab-escalation.js` | 18987 | `486bf4371210e54d` | PROBE p558: RAB escalation — sort/iterate/fill resize races + feature inventory |
| `p559-rab-oob-values.js` | 12962 | `b13f549d4e2c69fe` | PROBE p559: RAB iteration OOB value capture |
| `v900_fw1422_recon.html` | 4621 | `b022d87cd7f28014` | PROBE v900: 14.22 recon — engine fingerprint + capability map + Canvas UAF trigger |
| `v901_fontface_free_test.html` | 3750 | `077117e581dbd672` | v901_fontface_free_test.html |
| `v902_heap_scan.html` | 5598 | `28cec3aab5421a24` | v902_heap_scan.html |
| `v903_upstream_calibrated_scan.html` | 5386 | `35b124c96a2cae29` | v903_upstream_calibrated_scan.html |
| `v904_reclaim_type.html` | 3513 | `d6f0e5eb50c7be1b` | v904_reclaim_type.html |
| `v905_offset_invariant_scan.html` | 5006 | `08df1c9acf5954bf` | v905_offset_invariant_scan.html |
| `v906_state_buffer_orphan.html` | 4581 | `5c735bc87b84db66` | v906_state_buffer_orphan.html |
| `v907_state_buffer_orphan.html` | 3549 | `92cade8172421c99` | v907_state_buffer_orphan.html |
| `v908_dangle_state_buffer.html` | 4206 | `1a687ae5b0fb33f8` | v908_dangle_state_buffer.html |
| `v909_sync_free_state_buffer.html` | 3985 | `5010c08d8d88fdc3` | v909_sync_free_state_buffer.html |
| `v910_dense_sweep.html` | 4606 | `6695b250e8abf0e9` | v910_dense_sweep.html |
| `v911_differential_scan.html` | 8792 | `0b57208833335a2c` | v911_differential_scan.html |
| `v912_ab192_leak.html` | 4694 | `151093f92506d112` | v912_ab192_leak.html |
| `v913_fontface_pair_disc.html` | 11039 | `1e0661eb89c476e7` | v913_fontface_pair_disc.html |
| `v914_positive_control.html` | 8231 | `1d9cbebf9bad64d3` | v914_positive_control.html |
| `v915_forge_control.html` | 9297 | `0ff791f73e646b1d` | v915_forge_control.html |
| `v916_cell_everywhere.html` | 9512 | `b494cdc6ee86ebed` | v916_cell_everywhere.html |
| `v918_apng_overread2.html` | 10935 | `e169017a56b3e60a` | v918_apng_overread2.html |
| `v919_carrier_escalation.html` | 7127 | `66013c066ba4191e` | v919_carrier_escalation.html |
| `v920_p674b_killer_localization.html` | 9935 | `769242183b8b44eb` | v920_p674b_killer_localization.html |
| `v921_apng_trigger_grid.html` | 6586 | `633bee1af5869da1` | v921_apng_trigger_grid.html |
| `v922_field_surgery.html` | 7577 | `6a21e2b64a8a5b55` | v922_field_surgery.html |
| `v923_width_sweep.html` | 6429 | `be1ab03fa40be029` | v923_width_sweep.html |
| `v924_jit_presence.html` | 3480 | `3ab024d451303375` | v924_jit_presence.html |
| `v925_wasm_decider.html` | 2923 | `f4fce515c15324aa` | v925_wasm_decider.html |
| `v926_bitfit192_catalog.html` | 8213 | `246a078edf7580d0` | v926_bitfit192_catalog.html |
| `v927_24213_float_patterns.html` | 8267 | `dff6d07b1f3a89a3` | v927_24213_float_patterns.html |
| `v928_sortshrink_deepread.html` | 4362 | `ac26ba139a1fa40b` | v928_sortshrink_deepread.html |
| `v929_preforge_census.html` | 7460 | `2996d684da69c88c` | v929_preforge_census.html |
| `v930_repaired_census.html` | 8962 | `0160adc5a7a8e086` | v930_repaired_census.html |
| `v931_style_map.html` | 6567 | `6ac41e34ff505121` | v931_style_map.html |
