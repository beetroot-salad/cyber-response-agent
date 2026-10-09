# Garbage-page control — run record

Instrument: `defender/tests/_garbage_page_1025.py` (this record is written by it). Interpreter: `python` 3.11.15. Suite: `test_1025_page_contract.py`, `test_1025_page_verdict.py`, `test_1025_page_worlds.py`, `test_1025_page_stages.py`, `test_1025_page_records.py`.

A test is `green` when the stub SATISFIED it (the finding), `red-content` when its own assertion (or the fixture's page helper) refused the page, `red-other` when it failed for a reason no page stub can reach (the launcher hook, a reader arm, a lint, a subprocess import), `skipped` when pytest skipped it.

## Summary

| mode | tests | red-content | red-head | red-other | green | skipped |
|---|---|---|---|---|---|---|
| empty | 187 | 171 | 5 | 1 | 7 | 3 |
| garbage | 187 | 171 | 5 | 1 | 7 | 3 |
| skeleton | 187 | 170 | 5 | 1 | 8 | 3 |

## empty — green (7)

- `test_1025_byte_identity_across_two_interpreter_processes`
- `test_1025_how_the_operator_learns_where_the_page_is`
- `test_1025_grade_episode_reads_world_archive_through_the_same_screen_as_the_page`
- `test_1025_judge_render_reads_world_archive_through_the_same_screen_as_the_page`
- `test_1025_the_four_baseline_entries_naming_this_page_as_their_reader_are_gone_and_the_lint_is_green`
- `test_1025_the_new_modules_tree_reads_are_censused`
- `test_1025_the_root_stamp_reader_lives_in_the_record_names_home_beside_family_stamp_name`

## empty — red-head / red-other (6)

- `test_1025_a_render_fault_is_printed_and_changes_neither_the_exit_status_nor_judge_yaml` — red-head: launcher hook absent on HEAD; AssertionError raised at `test_1025_page_contract.py:250` (the test's line: `test_1025_page_contract.py:250`): 2026-10-09T09:21:56.858+00:00 INFO defender.learning.branch.cli primed 3 captured row(s) into /tmp/pytest-of-root/pytest
- `test_1025_a_render_that_raises_midway_keeps_the_previous_page` — red-head: fault injection: the stub is too fast for when_inside; Failed raised at `outcomes.py:163` (the test's line: `test_1025_page_contract.py:764`): DID NOT RAISE &lt;class &#x27;RuntimeError&#x27;&gt;
- `test_1025_an_interrupt_during_the_render` — red-head: fault injection: the stub is too fast for when_inside; Failed raised at `outcomes.py:163` (the test's line: `test_1025_page_contract.py:697`): DID NOT RAISE &lt;class &#x27;KeyboardInterrupt&#x27;&gt;
- `test_1025_draw_or_judge_yaml_record_is_rewritten_mid_render` — red-head: fault injection: the stub is too fast for when_inside; AssertionError raised at `test_1025_page_contract.py:606` (the test's line: `test_1025_page_contract.py:606`): the rewrite never landed inside the render
- `test_1025_judge_yaml_replaced_by_a_concurrent_re_grade_partway_through_one_render` — red-head: fault injection: the stub is too fast for when_inside; AssertionError raised at `test_1025_page_contract.py:588` (the test's line: `test_1025_page_contract.py:588`): the rewrite never landed inside the render
- `test_1025_the_page_module_reads_every_record_through_its_package_reader_spells_no_record_name_and_imports_no_private_helper` — red-other: raised outside the suite (the stub, a reader, pathlib); FileNotFoundError raised at `pathlib.py:1044` (the test's line: `test_1025_page_records.py:622`): [Errno 2] No such file or directory: &#x27;&lt;garbage-page-empty&gt;/visualize_episode.py&#x27;

## garbage — green (7)

- `test_1025_byte_identity_across_two_interpreter_processes`
- `test_1025_how_the_operator_learns_where_the_page_is`
- `test_1025_grade_episode_reads_world_archive_through_the_same_screen_as_the_page`
- `test_1025_judge_render_reads_world_archive_through_the_same_screen_as_the_page`
- `test_1025_the_four_baseline_entries_naming_this_page_as_their_reader_are_gone_and_the_lint_is_green`
- `test_1025_the_new_modules_tree_reads_are_censused`
- `test_1025_the_root_stamp_reader_lives_in_the_record_names_home_beside_family_stamp_name`

## garbage — red-head / red-other (6)

- `test_1025_a_render_fault_is_printed_and_changes_neither_the_exit_status_nor_judge_yaml` — red-head: launcher hook absent on HEAD; AssertionError raised at `test_1025_page_contract.py:250` (the test's line: `test_1025_page_contract.py:250`): 2026-10-09T09:22:12.272+00:00 INFO defender.learning.branch.cli primed 3 captured row(s) into /tmp/pytest-of-root/pytest
- `test_1025_a_render_that_raises_midway_keeps_the_previous_page` — red-head: fault injection: the stub is too fast for when_inside; Failed raised at `outcomes.py:163` (the test's line: `test_1025_page_contract.py:764`): DID NOT RAISE &lt;class &#x27;RuntimeError&#x27;&gt;
- `test_1025_an_interrupt_during_the_render` — red-head: fault injection: the stub is too fast for when_inside; Failed raised at `outcomes.py:163` (the test's line: `test_1025_page_contract.py:697`): DID NOT RAISE &lt;class &#x27;KeyboardInterrupt&#x27;&gt;
- `test_1025_draw_or_judge_yaml_record_is_rewritten_mid_render` — red-head: fault injection: the stub is too fast for when_inside; AssertionError raised at `test_1025_page_contract.py:606` (the test's line: `test_1025_page_contract.py:606`): the rewrite never landed inside the render
- `test_1025_judge_yaml_replaced_by_a_concurrent_re_grade_partway_through_one_render` — red-head: fault injection: the stub is too fast for when_inside; AssertionError raised at `test_1025_page_contract.py:588` (the test's line: `test_1025_page_contract.py:588`): the rewrite never landed inside the render
- `test_1025_the_page_module_reads_every_record_through_its_package_reader_spells_no_record_name_and_imports_no_private_helper` — red-other: raised outside the suite (the stub, a reader, pathlib); FileNotFoundError raised at `pathlib.py:1044` (the test's line: `test_1025_page_records.py:622`): [Errno 2] No such file or directory: &#x27;&lt;garbage-page-garbage&gt;/visualize_episode.py&#x27;

## skeleton — green (8)

- `test_1025_a_render_creates_or_changes_exactly_one_file_learning_html_and_touches_no_run_visualizations_mirror`
- `test_1025_byte_identity_across_two_interpreter_processes`
- `test_1025_how_the_operator_learns_where_the_page_is`
- `test_1025_grade_episode_reads_world_archive_through_the_same_screen_as_the_page`
- `test_1025_judge_render_reads_world_archive_through_the_same_screen_as_the_page`
- `test_1025_the_four_baseline_entries_naming_this_page_as_their_reader_are_gone_and_the_lint_is_green`
- `test_1025_the_new_modules_tree_reads_are_censused`
- `test_1025_the_root_stamp_reader_lives_in_the_record_names_home_beside_family_stamp_name`

## skeleton — red-head / red-other (6)

- `test_1025_a_render_fault_is_printed_and_changes_neither_the_exit_status_nor_judge_yaml` — red-head: launcher hook absent on HEAD; AssertionError raised at `test_1025_page_contract.py:250` (the test's line: `test_1025_page_contract.py:250`): 2026-10-09T09:22:27.921+00:00 INFO defender.learning.branch.cli primed 3 captured row(s) into /tmp/pytest-of-root/pytest
- `test_1025_a_render_that_raises_midway_keeps_the_previous_page` — red-head: fault injection: the stub is too fast for when_inside; Failed raised at `outcomes.py:163` (the test's line: `test_1025_page_contract.py:764`): DID NOT RAISE &lt;class &#x27;RuntimeError&#x27;&gt;
- `test_1025_an_interrupt_during_the_render` — red-head: fault injection: the stub is too fast for when_inside; Failed raised at `outcomes.py:163` (the test's line: `test_1025_page_contract.py:697`): DID NOT RAISE &lt;class &#x27;KeyboardInterrupt&#x27;&gt;
- `test_1025_draw_or_judge_yaml_record_is_rewritten_mid_render` — red-head: fault injection: the stub is too fast for when_inside; AssertionError raised at `test_1025_page_contract.py:606` (the test's line: `test_1025_page_contract.py:606`): the rewrite never landed inside the render
- `test_1025_judge_yaml_replaced_by_a_concurrent_re_grade_partway_through_one_render` — red-head: fault injection: the stub is too fast for when_inside; AssertionError raised at `test_1025_page_contract.py:588` (the test's line: `test_1025_page_contract.py:588`): the rewrite never landed inside the render
- `test_1025_the_page_module_reads_every_record_through_its_package_reader_spells_no_record_name_and_imports_no_private_helper` — red-other: raised outside the suite (the stub, a reader, pathlib); FileNotFoundError raised at `pathlib.py:1044` (the test's line: `test_1025_page_records.py:622`): [Errno 2] No such file or directory: &#x27;&lt;garbage-page-skeleton&gt;/visualize_episode.py&#x27;

## Every test, every mode (crash site of the red ones)

| test | empty | garbage | skeleton |
|---|---|---|---|
| `test_1025_a_link_into_an_unreadable_directory_at_a_records_name_is_that_slots_refusal` | skipped | skipped | skipped |
| `test_1025_a_link_planted_at_learning_html_is_refused_not_written_through` | red-content `test_1025_page_contract.py:162` | red-content `test_1025_page_contract.py:162` | red-content `test_1025_page_contract.py:162` |
| `test_1025_a_read_only_episode_directory` | skipped | skipped | skipped |
| `test_1025_a_refused_write_leaves_no_residue` | red-content `test_1025_page_contract.py:747` | red-content `test_1025_page_contract.py:747` | red-content `test_1025_page_contract.py:747` |
| `test_1025_a_render_creates_or_changes_exactly_one_file_learning_html_and_touches_no_run_visualizations_mirror` | red-content `test_1025_page_contract.py:193` | red-content `test_1025_page_contract.py:193` | green |
| `test_1025_a_render_fault_is_printed_and_changes_neither_the_exit_status_nor_judge_yaml` | red-head `test_1025_page_contract.py:250` | red-head `test_1025_page_contract.py:250` | red-head `test_1025_page_contract.py:250` |
| `test_1025_a_render_that_raises_midway_keeps_the_previous_page` | red-head `test_1025_page_contract.py:764` | red-head `test_1025_page_contract.py:764` | red-head `test_1025_page_contract.py:764` |
| `test_1025_an_interrupt_during_the_render` | red-head `test_1025_page_contract.py:697` | red-head `test_1025_page_contract.py:697` | red-head `test_1025_page_contract.py:697` |
| `test_1025_an_unhealthy_episode_renders_no_absolute_path_and_byte_identically_from_two_roots` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_contract.py:943` |
| `test_1025_both_archived_episodes_render_from_a_copied_dir_with_no_runs_base_store_or_checkout_and_the_bytes_do_not_depend_on_where` | red-content `test_1025_page_contract.py:500` | red-content `test_1025_page_contract.py:500` | red-content `test_1025_page_contract.py:500` |
| `test_1025_byte_identity_across_two_interpreter_processes` | green | green | green |
| `test_1025_cli_argument_names_an_existing_regular_file_not_a_directory` | red-content `test_1025_page_contract.py:340` | red-content `test_1025_page_contract.py:340` | red-content `test_1025_page_contract.py:340` |
| `test_1025_cli_invoked_with_no_positional_argument` | red-content `test_1025_page_contract.py:330` | red-content `test_1025_page_contract.py:330` | red-content `test_1025_page_contract.py:330` |
| `test_1025_draw_or_judge_yaml_record_is_rewritten_mid_render` | red-head `test_1025_page_contract.py:606` | red-head `test_1025_page_contract.py:606` | red-head `test_1025_page_contract.py:606` |
| `test_1025_episode_dir_given_through_a_symlink` | red-content `test_1025_page_contract.py:628` | red-content `test_1025_page_contract.py:628` | red-content `test_1025_page_contract.py:628` |
| `test_1025_every_class_the_page_emits_has_a_rule_in_the_css_it_ships` | red-content `test_1025_page_contract.py:847` | red-content `test_1025_page_contract.py:847` | red-content `test_1025_page_contract.py:847` |
| `test_1025_family_yaml_has_invalid_yaml_syntax` | red-content `test_1025_page_contract.py:398` | red-content `test_1025_page_contract.py:398` | red-content `test_1025_page_contract.py:398` |
| `test_1025_family_yaml_is_a_directory_not_a_file` | red-content `test_1025_page_contract.py:398` | red-content `test_1025_page_contract.py:398` | red-content `test_1025_page_contract.py:398` |
| `test_1025_family_yaml_is_zero_bytes` | red-content `test_1025_page_contract.py:398` | red-content `test_1025_page_contract.py:398` | red-content `test_1025_page_contract.py:398` |
| `test_1025_family_yaml_top_level_document_is_a_list_not_a_mapping` | red-content `test_1025_page_contract.py:398` | red-content `test_1025_page_contract.py:398` | red-content `test_1025_page_contract.py:398` |
| `test_1025_how_the_operator_learns_where_the_page_is` | green | green | green |
| `test_1025_judge_yaml_replaced_by_a_concurrent_re_grade_partway_through_one_render` | red-head `test_1025_page_contract.py:588` | red-head `test_1025_page_contract.py:588` | red-head `test_1025_page_contract.py:588` |
| `test_1025_preflight_refused_episode_and_the_page` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_contract.py:278` |
| `test_1025_questioner_or_preflight_abort_leaves_a_partial_directory` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_contract.py:659` |
| `test_1025_relative_and_trailing_slash_arguments` | red-content `test_1025_page_contract.py:365` | red-content `test_1025_page_contract.py:365` | red-content `test_1025_page_contract.py:365` |
| `test_1025_render_episode_writes_learning_html_beside_judge_yaml_and_returns_its_path` | red-content `test_1025_page_contract.py:114` | red-content `test_1025_page_contract.py:115` | red-content `test_1025_page_contract.py:115` |
| `test_1025_repair_and_regrade_leaves_the_page_stale` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_contract.py:521` |
| `test_1025_runs_base_and_episodes_base_env_vars_point_at_nonexistent_paths_during_render` | red-content `test_1025_page_contract.py:388` | red-content `test_1025_page_contract.py:388` | red-content `test_1025_page_contract.py:389` |
| `test_1025_standalone_render_of_a_live_episode` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_contract.py:732` |
| `test_1025_the_cli_exit_status_for_a_degraded_page` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_contract.py:312` |
| `test_1025_the_launcher_renders_the_page_after_the_judge_frame_with_every_step_on_it` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_contract.py:214` |
| `test_1025_the_standalone_script_runs_with_no_pythonpath_from_any_cwd` | red-content `test_1025_page_contract.py:900` | red-content `test_1025_page_contract.py:900` | red-content `test_1025_page_contract.py:900` |
| `test_1025_two_renders_in_flight_against_the_same_episode_dir` | red-content `test_1025_page_contract.py:572` | red-content `test_1025_page_contract.py:572` | red-content `test_1025_page_contract.py:572` |
| `test_1025_visualize_episode_cli_exits_zero_on_an_episode_dir_and_one_with_no_page_otherwise` | red-content `test_1025_page_contract.py:145` | red-content `test_1025_page_contract.py:145` | red-content `test_1025_page_contract.py:145` |
| `test_1025_a_malformed_record_versus_an_absent_one` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_records.py:433` |
| `test_1025_a_served_ledger_present_but_truncated` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_records.py:493` |
| `test_1025_an_alias_planted_at_each_record_name` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_records.py:405` |
| `test_1025_an_unreadable_regular_file_at_a_record_name` | skipped | skipped | skipped |
| `test_1025_each_record_in_the_records_section_renders_as_absent_when_missing_and_its_content_when_present` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_records.py:135` |
| `test_1025_episode_root_provenance_json_is_a_directory` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_records.py:572` |
| `test_1025_grade_episode_reads_world_archive_through_the_same_screen_as_the_page` | green | green | green |
| `test_1025_grade_episode_still_grades_an_episode_whose_samples_yaml_is_malformed` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_records.py:780` |
| `test_1025_judge_render_reads_world_archive_through_the_same_screen_as_the_page` | green | green | green |
| `test_1025_judge_yaml_has_invalid_yaml_syntax` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_records.py:307` |
| `test_1025_malformed_samples_or_provenance_reads_as_absent` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_records.py:381` |
| `test_1025_markup_in_every_model_authored_field_renders_as_text_on_every_section` | red-content `test_1025_page_records.py:186` | red-content `test_1025_page_records.py:186` | red-content `test_1025_page_records.py:186` |
| `test_1025_markup_in_the_records_no_planted_field_covers` | red-content `test_1025_page_records.py:229` | red-content `test_1025_page_records.py:229` | red-content `test_1025_page_records.py:229` |
| `test_1025_non_ascii_and_control_characters_in_rendered_strings` | red-content `test_1025_page_records.py:246` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` |
| `test_1025_one_malformed_sidecar_record_sits_beside_otherwise_intact_ones` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_records.py:521` |
| `test_1025_outcome_yaml_cannot_be_read_as_the_record` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_records.py:361` |
| `test_1025_the_episode_root_and_a_worlds_provenance_json_use_different_key_shapes_at_the_same_file_name` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_records.py:591` |
| `test_1025_the_four_baseline_entries_naming_this_page_as_their_reader_are_gone_and_the_lint_is_green` | green | green | green |
| `test_1025_the_new_modules_tree_reads_are_censused` | green | green | green |
| `test_1025_the_page_encodes_with_errors_replace_before_the_guarded_write` | red-content `test_1025_page_records.py:286` | red-content `test_1025_page_records.py:286` | red-content `test_1025_page_records.py:286` |
| `test_1025_the_page_module_reads_every_record_through_its_package_reader_spells_no_record_name_and_imports_no_private_helper` | red-other `test_1025_page_records.py:622` | red-other `test_1025_page_records.py:622` | red-other `test_1025_page_records.py:622` |
| `test_1025_the_root_stamp_reader_lives_in_the_record_names_home_beside_family_stamp_name` | green | green | green |
| `test_1025_timing_json_is_present_but_not_the_stageclock_record_shape` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_records.py:325` |
| `test_1025_timing_json_names_a_step_outside_the_steps_vocabulary` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_records.py:346` |
| `test_1025_a_big_integer_literal_is_that_fields_own_absence` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_stages.py:683` |
| `test_1025_a_framed_trace_row_carries_a_failure_field_instead_of_a_reply` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` |
| `test_1025_a_hostile_wire_logs_trace_stem` | red-content `test_1025_page_stages.py:555` | red-content `test_1025_page_stages.py:555` | red-content `test_1025_page_stages.py:555` |
| `test_1025_a_judge_stem_with_a_non_ascii_digit_is_unattributed_not_a_draw` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_stages.py:721` |
| `test_1025_a_repeated_steps_own_wall_excludes_an_inverted_sibling_entry` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_stages.py:266` |
| `test_1025_a_result_event_that_is_forged_or_misplaced` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_stages.py:595` |
| `test_1025_a_result_event_with_no_total_cost_usd_key_at_all` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_stages.py:619` |
| `test_1025_a_sibling_tool_trace_jsonls_final_row_is_not_a_result_event` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_stages.py:443` |
| `test_1025_a_steps_ended_at_sorts_before_its_started_at` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_stages.py:240` |
| `test_1025_a_sum_of_finite_values_that_overflows_reads_the_dash` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_stages.py:708` |
| `test_1025_a_symlinked_tool_trace_in_a_run_dir` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_stages.py:634` |
| `test_1025_a_trace_response_row_names_a_model_absent_from_the_pricing_table` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` |
| `test_1025_a_trace_whose_last_line_is_torn` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` |
| `test_1025_a_trace_with_a_request_row_and_no_response_row` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` |
| `test_1025_a_usage_block_with_a_negative_or_overflowing_count_is_unpriced` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` |
| `test_1025_a_very_long_unbroken_token` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` |
| `test_1025_each_questioner_and_judge_trace_renders_a_labelled_block_family_first_with_the_framed_prompt_and_every_response_row` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` |
| `test_1025_judge_trace_stems_with_underscored_labels_and_two_digit_draws` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_stages.py:374` |
| `test_1025_questioner_request_rows_have_no_framed_file` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` |
| `test_1025_render_against_a_still_running_sibling_with_no_result_event_yet` | red-content `test_1025_page_stages.py:456` | red-content `test_1025_page_stages.py:456` | red-content `test_1025_page_stages.py:457` |
| `test_1025_response_rows_missing_usage_model_or_duration` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` |
| `test_1025_six_transcript_streams_and_one_set_of_controls` | red-content `test_1025_page_stages.py:530` | red-content `test_1025_page_stages.py:530` | red-content `test_1025_page_stages.py:530` |
| `test_1025_stage_costs_sum_response_row_usage_and_each_runs_result_event_and_a_run_with_no_trace_shows_no_cost_not_zero` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_stages.py:163` |
| `test_1025_the_runs_row_has_two_clocks` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_stages.py:297` |
| `test_1025_the_stage_table_has_one_row_per_step_runs_expanded_per_run_dir_wall_only_rows_and_a_total_that_says_what_it_excludes` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_stages.py:98` |
| `test_1025_timing_json_lists_the_same_step_twice_or_out_of_launch_order` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_stages.py:573` |
| `test_1025_trace_present_but_framed_absent` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` |
| `test_1025_trace_prompt_or_reply_contains_a_literal_pre_or_script_close_tag` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` |
| `test_1025_what_the_header_wall_covers` | red-content `_episode_1025.py:1041` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_stages.py:283` |
| `test_1025_without_timing_json_the_axis_is_model_time_with_a_labelled_lower_bound_and_with_it_the_launchers_wall_per_step` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_stages.py:121` |
| `test_1025_a_draw_document_is_missing_its_findings_key_entirely` | red-content `test_1025_page_verdict.py:116` | red-content `test_1025_page_verdict.py:116` | red-content `test_1025_page_verdict.py:740` |
| `test_1025_a_draw_document_is_torn_mid_write` | red-content `test_1025_page_verdict.py:678` | red-content `test_1025_page_verdict.py:678` | red-content `test_1025_page_verdict.py:678` |
| `test_1025_a_draw_document_that_is_only_a_failure_reason` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_verdict.py:830` |
| `test_1025_a_finding_id_recorded_in_judge_yaml_names_a_world_draw_index_triple_absent_from_every_draw_document` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` |
| `test_1025_a_finding_row_carries_a_non_null_world_field_that_disagrees_with_its_directory` | red-content `test_1025_page_verdict.py:1112` | red-content `test_1025_page_verdict.py:1112` | red-content `test_1025_page_verdict.py:1112` |
| `test_1025_a_finding_that_is_not_a_mapping` | red-content `test_1025_page_verdict.py:810` | red-content `test_1025_page_verdict.py:810` | red-content `test_1025_page_verdict.py:810` |
| `test_1025_a_findings_disposition_reproduces_the_enqueues_partition_unqueueable_blocked_by_verdict_or_enqueued` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` |
| `test_1025_a_gradable_row_whose_draws_never_ran` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_verdict.py:1227` |
| `test_1025_a_non_canonically_spelled_verdict_word_still_blocks_the_judged_worlds_defender_findings` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` |
| `test_1025_a_not_graded_page_below_the_band` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_verdict.py:283` |
| `test_1025_a_not_graded_stamp_carries_a_field_this_readers_schema_has_never_seen` | red-content `test_1025_page_verdict.py:1060` | red-content `test_1025_page_verdict.py:1060` | red-content `test_1025_page_verdict.py:1060` |
| `test_1025_a_not_graded_stamp_renders_its_reason_and_no_tiles_cards_or_findings_table` | red-content `test_1025_page_verdict.py:257` | red-content `test_1025_page_verdict.py:257` | red-content `test_1025_page_verdict.py:258` |
| `test_1025_a_world_drawn_twice_renders_both_draws_findings_once_each_in_numeric_draw_order_via_draws_on_disk` | red-content `test_1025_page_verdict.py:502` | red-content `test_1025_page_verdict.py:502` | red-content `test_1025_page_verdict.py:502` |
| `test_1025_a_world_finding_refused_for_citing_an_unavailable_sample` | red-content `test_1025_page_verdict.py:853` | red-content `test_1025_page_verdict.py:853` | red-content `test_1025_page_verdict.py:853` |
| `test_1025_an_empty_family_outcome_is_the_badge_word_not_an_absence` | red-content `_episode_1025.py:1041` | red-content `_episode_1025.py:1041` | red-content `test_1025_page_verdict.py:1324` |
| `test_1025_an_episode_with_no_judge_yaml_still_renders_its_stages_and_worlds_and_says_there_is_no_grade_record` | red-content `test_1025_page_verdict.py:316` | red-content `test_1025_page_verdict.py:316` | red-content `test_1025_page_verdict.py:316` |
| `test_1025_an_episode_with_only_the_control` | red-content `test_1025_page_verdict.py:116` | red-content `test_1025_page_verdict.py:116` | red-content `test_1025_page_verdict.py:1252` |
| `test_1025_an_unqueueable_line_that_matches_no_rendered_finding` | red-content `_episode_1025.py:1041` | red-content `_episode_1025.py:1041` | red-content `test_1025_page_verdict.py:1171` |
| `test_1025_bucket_value_outside_the_closed_or_open_vocabularies` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` |
| `test_1025_draw_directory_holds_a_file_stem_written_with_a_non_ascii_digit` | red-content `test_1025_page_verdict.py:1095` | red-content `test_1025_page_verdict.py:1095` | red-content `test_1025_page_verdict.py:1095` |
| `test_1025_draw_directory_holds_both_1_yaml_and_01_yaml` | red-content `test_1025_page_verdict.py:1079` | red-content `test_1025_page_verdict.py:1079` | red-content `test_1025_page_verdict.py:1079` |
| `test_1025_draw_documents_exist_but_judge_yaml_does_not` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_verdict.py:340` |
| `test_1025_draw_index_beyond_the_recorded_completed_draw_count` | red-content `test_1025_page_verdict.py:766` | red-content `test_1025_page_verdict.py:766` | red-content `test_1025_page_verdict.py:766` |
| `test_1025_every_finding_across_per_draw_docs_and_family_draws_renders_exactly_once_keyed_world_draw_index` | red-content `test_1025_page_verdict.py:365` | red-content `test_1025_page_verdict.py:365` | red-content `test_1025_page_verdict.py:365` |
| `test_1025_family_call_faulted_after_writing_a_draw` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_verdict.py:1203` |
| `test_1025_family_drawn_several_times_with_a_dissenting_draw` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_verdict.py:914` |
| `test_1025_findings_render_one_table_per_addressee_with_the_seven_columns_family_rows_at_family_level_and_dropped_counts_per_draw` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` |
| `test_1025_identical_findings_under_two_draws` | red-content `test_1025_page_verdict.py:1187` | red-content `test_1025_page_verdict.py:1187` | red-content `test_1025_page_verdict.py:1187` |
| `test_1025_judge_yaml_carries_a_top_level_field_this_readers_schema_has_never_seen` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_verdict.py:1038` |
| `test_1025_judge_yaml_is_a_symlink_whose_target_is_a_different_episodes_judge_yaml` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_verdict.py:1006` |
| `test_1025_judge_yaml_is_present_with_an_empty_worlds_array_and_no_not_graded_stamp` | red-content `test_1025_page_verdict.py:116` | red-content `test_1025_page_verdict.py:116` | red-content `test_1025_page_verdict.py:1026` |
| `test_1025_malformed_replies_and_gaps_in_draw_numbering` | red-content `test_1025_page_verdict.py:1133` | red-content `test_1025_page_verdict.py:1133` | red-content `test_1025_page_verdict.py:1133` |
| `test_1025_manifest_fields_the_slot_bindings_never_name` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_verdict.py:940` |
| `test_1025_no_hand_written_sentence_from_the_artifact_appears_while_every_templated_count_sentence_does` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_verdict.py:576` |
| `test_1025_one_card_per_graded_world_with_declared_to_verdict_bucket_and_systems_heading_and_a_footer_linking_its_findings_group` | red-content `test_1025_page_verdict.py:543` | red-content `test_1025_page_verdict.py:543` | red-content `test_1025_page_verdict.py:543` |
| `test_1025_one_draw_document_is_a_symlink_to_a_file_outside_the_episode` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_verdict.py:699` |
| `test_1025_queue_accounting_lists_per_queue_rows_destination_as_recorded_unqueueable_malformed_and_dropped_counts` | red-content `test_1025_page_verdict.py:523` | red-content `test_1025_page_verdict.py:523` | red-content `test_1025_page_verdict.py:525` |
| `test_1025_record_fields_no_slot_binds` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` |
| `test_1025_recorded_finding_ids_carry_a_different_episode_prefix` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` |
| `test_1025_render_reflects_a_not_graded_to_graded_transition_across_two_calls` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_verdict.py:1287` |
| `test_1025_render_when_family_judge_dir_exists_but_is_empty` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_verdict.py:1271` |
| `test_1025_subject_field_holds_a_value_outside_defender_and_world` | red-content `test_1025_page_verdict.py:784` | red-content `test_1025_page_verdict.py:784` | red-content `test_1025_page_verdict.py:784` |
| `test_1025_the_badge_is_family_outcome_falling_back_to_verdict_word_and_the_meta_line_carries_episode_outcome_and_verdict_word` | red-content `test_1025_page_verdict.py:199` | red-content `test_1025_page_verdict.py:199` | red-content `test_1025_page_verdict.py:200` |
| `test_1025_the_episode_level_verdicts_justification` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` |
| `test_1025_the_lede_lists_family_draw_findings_verbatim_grouped_by_draw_or_opens_with_the_templated_line_when_there_is_no_family_draw` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_verdict.py:162` |
| `test_1025_the_same_finding_id_string_appears_in_two_different_draw_documents` | red-content `test_1025_page_verdict.py:754` | red-content `test_1025_page_verdict.py:754` | red-content `test_1025_page_verdict.py:754` |
| `test_1025_the_verdict_tile_carries_judged_and_verdict_equals_declared_counts_on_both_archives` | red-content `test_1025_page_verdict.py:116` | red-content `test_1025_page_verdict.py:116` | red-content `test_1025_page_verdict.py:217` |
| `test_1025_tile_one_reads_verdict_and_declared_through_the_vocabularys_normalizer` | red-content `test_1025_page_verdict.py:116` | red-content `test_1025_page_verdict.py:116` | red-content `test_1025_page_verdict.py:1312` |
| `test_1025_tiles_two_to_four_carry_judged_of_rows_with_reasons_queued_of_total_split_and_cost_with_the_labelled_lower_bound` | red-content `test_1025_page_verdict.py:116` | red-content `test_1025_page_verdict.py:116` | red-content `test_1025_page_verdict.py:235` |
| `test_1025_top_level_enqueue_counts_disagree_with_the_rows_the_page_walks` | red-content `_episode_1025.py:1041` | red-content `_episode_1025.py:1041` | red-content `test_1025_page_verdict.py:648` |
| `test_1025_unqueueable_reason_text_contains_the_page_join_delimiter` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` |
| `test_1025_verdict_word_outside_the_five_known_values` | red-content `test_1025_page_verdict.py:116` | red-content `test_1025_page_verdict.py:116` | red-content `test_1025_page_verdict.py:961` |
| `test_1025_a_bucket_or_reason_word_used_as_an_attribute_value` | red-content `test_1025_page_worlds.py:484` | red-content `test_1025_page_worlds.py:484` | red-content `test_1025_page_worlds.py:484` |
| `test_1025_a_declared_world_with_no_run_directory` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` |
| `test_1025_a_gather_summary_stem_that_is_hostile` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_worlds.py:461` |
| `test_1025_a_judge_trace_for_a_world_or_draw_the_record_lacks` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_worlds.py:610` |
| `test_1025_a_lead_id_that_names_no_single_file_reads_nothing_and_renders_the_guards_sentence` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_worlds.py:333` |
| `test_1025_a_manifest_label_off_the_token_alphabet_never_reaches_a_frame_slot` | red-content `test_1025_page_worlds.py:419` | red-content `test_1025_page_worlds.py:419` | red-content `test_1025_page_worlds.py:419` |
| `test_1025_a_missing_or_unreadable_served_ledger_costs_the_leads_block_only_the_ledger` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_worlds.py:1140` |
| `test_1025_a_non_markdown_entry_under_gather_summaries_is_invisible_to_the_leads_block` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_worlds.py:1163` |
| `test_1025_a_roster_labels_own_draw_past_a_small_fixed_bound` | red-content `test_1025_page_worlds.py:633` | red-content `test_1025_page_worlds.py:633` | red-content `test_1025_page_worlds.py:633` |
| `test_1025_a_run_dir_with_a_result_event_and_no_runtime_html` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_worlds.py:696` |
| `test_1025_a_run_directory_symlink_or_dir_pointer_naming_a_symlinked_final_component` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_worlds.py:868` |
| `test_1025_a_run_directory_whose_name_is_not_episode_dash_label` | red-content `test_1025_page_worlds.py:648` | red-content `test_1025_page_worlds.py:648` | red-content `test_1025_page_worlds.py:648` |
| `test_1025_a_sibling_process_exited_non_zero` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` |
| `test_1025_a_world_section_is_not_graded_ungradable_with_its_reason_or_graded_and_never_confuses_the_three` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_worlds.py:157` |
| `test_1025_a_world_that_ran_but_was_never_archived` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` |
| `test_1025_alert_fields_reach_the_header_frame` | red-content `_episode_1025.py:1041` | red-content `test_1025_page_worlds.py:981` | red-content `test_1025_page_worlds.py:981` |
| `test_1025_axis_text_engineered_to_read_as_more_of_the_templated_sentence` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_worlds.py:506` |
| `test_1025_each_missing_archived_leaf_names_itself` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_worlds.py:1118` |
| `test_1025_each_world_links_to_runs_episode_world_runtime_html_relatively_and_the_run_dir_pointer_is_never_the_source` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_worlds.py:247` |
| `test_1025_every_step_in_steps_order_and_every_directory_under_runs_has_its_section_the_control_included` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_worlds.py:134` |
| `test_1025_gather_summaries_holds_a_file_that_is_not_markdown` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_worlds.py:888` |
| `test_1025_headings_carry_substituted_counts_the_worlds_guide_uses_each_axis_verbatim_and_the_nav_iterates_the_same_sets_as_the_sections` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_worlds.py:277` |
| `test_1025_investigation_md_is_present_but_unreadable` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_worlds.py:899` |
| `test_1025_judge_yaml_worlds_row_names_a_label_absent_from_family_yaml_and_runs` | red-content `test_1025_page_worlds.py:526` | red-content `test_1025_page_worlds.py:526` | red-content `test_1025_page_worlds.py:526` |
| `test_1025_leftover_draw_documents_under_a_world_the_record_excludes` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` |
| `test_1025_markup_in_lead_params_raw_command_and_resolutions` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_worlds.py:1010` |
| `test_1025_no_worlds_alert_json_carries_an_alert_id` | red-content `_episode_1025.py:1041` | red-content `test_1025_page_worlds.py:914` | red-content `test_1025_page_worlds.py:914` |
| `test_1025_partial_copy_missing_served_or_worlds_or_wire_logs` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_worlds.py:1053` |
| `test_1025_per_world_leads_are_referenced_leads_union_gather_summary_stems_with_their_chains_and_exclude_pre_branch_leads` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_worlds.py:305` |
| `test_1025_phantom_family_draw_on_an_episode_with_no_family_judge_call` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_worlds.py:597` |
| `test_1025_phantom_world_judge_dir_absent_from_manifest_and_from_runs` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_worlds.py:579` |
| `test_1025_record_declared_and_manifest_declared_disagree` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_worlds.py:747` |
| `test_1025_render_against_a_world_archive_mid_copy` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_worlds.py:846` |
| `test_1025_render_before_a_worlds_scrub_verdict_sidecar_is_written` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_worlds.py:784` |
| `test_1025_render_when_a_graded_world_has_no_matching_runs_dir` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_worlds.py:682` |
| `test_1025_runs_pruned_after_the_grade` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_worlds.py:709` |
| `test_1025_symlink_planted_at_a_leaf_file_the_page_reads_inside_a_world` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_worlds.py:930` |
| `test_1025_the_artifacts_anchor_ids_exist_and_every_nav_href_resolves_to_an_id_on_the_page` | red-content `test_1025_page_worlds.py:350` | red-content `test_1025_page_worlds.py:350` | red-content `test_1025_page_worlds.py:350` |
| `test_1025_the_control_is_identified_how` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_worlds.py:808` |
| `test_1025_the_control_world_renders_no_row_derived_parts` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_worlds.py:769` |
| `test_1025_the_header_names_the_episode_alert_rule_source_run_and_branch_point_knobs_and_lessons_commit_never_defender_run` | red-content `test_1025_page_worlds.py:377` | red-content `test_1025_page_worlds.py:380` | red-content `test_1025_page_worlds.py:380` |
| `test_1025_the_world_block_shows_the_verdict_line_and_the_stored_bucket_never_a_recomputed_one` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_worlds.py:191` |
| `test_1025_the_worlds_and_leads_headings_count_exactly_the_sections_under_them` | red-content `test_1025_page_worlds.py:1101` | red-content `test_1025_page_worlds.py:1101` | red-content `test_1025_page_worlds.py:1101` |
| `test_1025_ungradable_rows_from_the_early_tiers_carry_no_flags` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_worlds.py:728` |
| `test_1025_ungradable_world_carries_a_populated_judge_directory` | red-content `test_1025_page_worlds.py:541` | red-content `test_1025_page_worlds.py:541` | red-content `test_1025_page_worlds.py:541` |
| `test_1025_world_chips_carry_the_judge_models_systems_and_every_draws_answer_and_never_a_default` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_worlds.py:214` |
| `test_1025_world_or_lead_directory_name_carries_attribute_or_tag_breaking_characters` | red-content `_episode_1025.py:1019` | red-content `_episode_1025.py:1019` | red-content `test_1025_page_worlds.py:443` |
