# Garbage-page control — run record

Instrument: `defender/tests/_garbage_page_1025.py` (this record is written by it). Interpreter: `python3` 3.11.15. Suite: `test_1025_page_contract.py`, `test_1025_page_verdict.py`, `test_1025_page_worlds.py`, `test_1025_page_stages.py`, `test_1025_page_records.py`.

A test is `green` when the stub SATISFIED it (the finding), `red-content` when its own assertion (or the fixture's page helper) refused the page, `red-other` when it failed for a reason no page stub can reach (the launcher hook, a reader arm, a lint, a subprocess import), `skipped` when pytest skipped it.

## Summary

| mode | tests | red-content | red-head | red-other | green | skipped |
|---|---|---|---|---|---|---|
| empty | 180 | 165 | 5 | 1 | 7 | 2 |
| garbage | 180 | 165 | 5 | 1 | 7 | 2 |
| skeleton | 180 | 164 | 5 | 1 | 8 | 2 |

## empty — green (7)

- `test_1025_byte_identity_across_two_interpreter_processes`
- `test_1025_how_the_operator_learns_where_the_page_is`
- `test_1025_grade_episode_reads_world_archive_through_the_same_screen_as_the_page`
- `test_1025_judge_render_reads_world_archive_through_the_same_screen_as_the_page`
- `test_1025_the_four_baseline_entries_naming_this_page_as_their_reader_are_gone_and_the_lint_is_green`
- `test_1025_the_new_modules_tree_reads_are_censused`
- `test_1025_the_root_stamp_reader_lives_in_the_record_names_home_beside_family_stamp_name`

## empty — red-head / red-other (6)

- `test_1025_a_render_fault_is_printed_and_changes_neither_the_exit_status_nor_judge_yaml` — red-head: launcher hook absent on HEAD; AssertionError raised at `test_1025_page_contract.py:244` (the test's line: `test_1025_page_contract.py:244`): [branch] primed 1 captured row(s) into /tmp/pytest-of-root/pytest-12285/test_1025_a_render_fault_is_pr0/episodes-root/20
- `test_1025_a_render_that_raises_midway_keeps_the_previous_page` — red-head: fault injection: the stub is too fast for when_inside; Failed raised at `outcomes.py:163` (the test's line: `test_1025_page_contract.py:760`): DID NOT RAISE &lt;class &#x27;RuntimeError&#x27;&gt;
- `test_1025_an_interrupt_during_the_render` — red-head: fault injection: the stub is too fast for when_inside; Failed raised at `outcomes.py:163` (the test's line: `test_1025_page_contract.py:695`): DID NOT RAISE &lt;class &#x27;KeyboardInterrupt&#x27;&gt;
- `test_1025_draw_or_judge_yaml_record_is_rewritten_mid_render` — red-head: fault injection: the stub is too fast for when_inside; AssertionError raised at `test_1025_page_contract.py:613` (the test's line: `test_1025_page_contract.py:613`): the rewrite never landed inside the render
- `test_1025_judge_yaml_replaced_by_a_concurrent_re_grade_partway_through_one_render` — red-head: fault injection: the stub is too fast for when_inside; AssertionError raised at `test_1025_page_contract.py:595` (the test's line: `test_1025_page_contract.py:595`): the rewrite never landed inside the render
- `test_1025_the_page_module_reads_every_record_through_its_package_reader_spells_no_record_name_and_imports_no_private_helper` — red-other: raised outside the suite (the stub, a reader, pathlib); FileNotFoundError raised at `pathlib.py:1044` (the test's line: `test_1025_page_records.py:620`): [Errno 2] No such file or directory: &#x27;&lt;garbage-page-empty&gt;/visualize_episode.py&#x27;

## garbage — green (7)

- `test_1025_byte_identity_across_two_interpreter_processes`
- `test_1025_how_the_operator_learns_where_the_page_is`
- `test_1025_grade_episode_reads_world_archive_through_the_same_screen_as_the_page`
- `test_1025_judge_render_reads_world_archive_through_the_same_screen_as_the_page`
- `test_1025_the_four_baseline_entries_naming_this_page_as_their_reader_are_gone_and_the_lint_is_green`
- `test_1025_the_new_modules_tree_reads_are_censused`
- `test_1025_the_root_stamp_reader_lives_in_the_record_names_home_beside_family_stamp_name`

## garbage — red-head / red-other (6)

- `test_1025_a_render_fault_is_printed_and_changes_neither_the_exit_status_nor_judge_yaml` — red-head: launcher hook absent on HEAD; AssertionError raised at `test_1025_page_contract.py:244` (the test's line: `test_1025_page_contract.py:244`): [branch] primed 1 captured row(s) into /tmp/pytest-of-root/pytest-12286/test_1025_a_render_fault_is_pr0/episodes-root/20
- `test_1025_a_render_that_raises_midway_keeps_the_previous_page` — red-head: fault injection: the stub is too fast for when_inside; Failed raised at `outcomes.py:163` (the test's line: `test_1025_page_contract.py:760`): DID NOT RAISE &lt;class &#x27;RuntimeError&#x27;&gt;
- `test_1025_an_interrupt_during_the_render` — red-head: fault injection: the stub is too fast for when_inside; Failed raised at `outcomes.py:163` (the test's line: `test_1025_page_contract.py:695`): DID NOT RAISE &lt;class &#x27;KeyboardInterrupt&#x27;&gt;
- `test_1025_draw_or_judge_yaml_record_is_rewritten_mid_render` — red-head: fault injection: the stub is too fast for when_inside; AssertionError raised at `test_1025_page_contract.py:613` (the test's line: `test_1025_page_contract.py:613`): the rewrite never landed inside the render
- `test_1025_judge_yaml_replaced_by_a_concurrent_re_grade_partway_through_one_render` — red-head: fault injection: the stub is too fast for when_inside; AssertionError raised at `test_1025_page_contract.py:595` (the test's line: `test_1025_page_contract.py:595`): the rewrite never landed inside the render
- `test_1025_the_page_module_reads_every_record_through_its_package_reader_spells_no_record_name_and_imports_no_private_helper` — red-other: raised outside the suite (the stub, a reader, pathlib); FileNotFoundError raised at `pathlib.py:1044` (the test's line: `test_1025_page_records.py:620`): [Errno 2] No such file or directory: &#x27;&lt;garbage-page-garbage&gt;/visualize_episode.py&#x27;

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

- `test_1025_a_render_fault_is_printed_and_changes_neither_the_exit_status_nor_judge_yaml` — red-head: launcher hook absent on HEAD; AssertionError raised at `test_1025_page_contract.py:244` (the test's line: `test_1025_page_contract.py:244`): [branch] primed 1 captured row(s) into /tmp/pytest-of-root/pytest-12287/test_1025_a_render_fault_is_pr0/episodes-root/20
- `test_1025_a_render_that_raises_midway_keeps_the_previous_page` — red-head: fault injection: the stub is too fast for when_inside; Failed raised at `outcomes.py:163` (the test's line: `test_1025_page_contract.py:760`): DID NOT RAISE &lt;class &#x27;RuntimeError&#x27;&gt;
- `test_1025_an_interrupt_during_the_render` — red-head: fault injection: the stub is too fast for when_inside; Failed raised at `outcomes.py:163` (the test's line: `test_1025_page_contract.py:695`): DID NOT RAISE &lt;class &#x27;KeyboardInterrupt&#x27;&gt;
- `test_1025_draw_or_judge_yaml_record_is_rewritten_mid_render` — red-head: fault injection: the stub is too fast for when_inside; AssertionError raised at `test_1025_page_contract.py:613` (the test's line: `test_1025_page_contract.py:613`): the rewrite never landed inside the render
- `test_1025_judge_yaml_replaced_by_a_concurrent_re_grade_partway_through_one_render` — red-head: fault injection: the stub is too fast for when_inside; AssertionError raised at `test_1025_page_contract.py:595` (the test's line: `test_1025_page_contract.py:595`): the rewrite never landed inside the render
- `test_1025_the_page_module_reads_every_record_through_its_package_reader_spells_no_record_name_and_imports_no_private_helper` — red-other: raised outside the suite (the stub, a reader, pathlib); FileNotFoundError raised at `pathlib.py:1044` (the test's line: `test_1025_page_records.py:620`): [Errno 2] No such file or directory: &#x27;&lt;garbage-page-skeleton&gt;/visualize_episode.py&#x27;

## Every test, every mode (crash site of the red ones)

| test | empty | garbage | skeleton |
|---|---|---|---|
| `test_1025_a_link_planted_at_learning_html_is_refused_not_written_through` | red-content `test_1025_page_contract.py:160` | red-content `test_1025_page_contract.py:160` | red-content `test_1025_page_contract.py:160` |
| `test_1025_a_read_only_episode_directory` | skipped | skipped | skipped |
| `test_1025_a_refused_write_leaves_no_residue` | red-content `test_1025_page_contract.py:743` | red-content `test_1025_page_contract.py:743` | red-content `test_1025_page_contract.py:743` |
| `test_1025_a_render_creates_or_changes_exactly_one_file_learning_html_and_touches_no_run_visualizations_mirror` | red-content `test_1025_page_contract.py:187` | red-content `test_1025_page_contract.py:187` | green |
| `test_1025_a_render_fault_is_printed_and_changes_neither_the_exit_status_nor_judge_yaml` | red-head `test_1025_page_contract.py:244` | red-head `test_1025_page_contract.py:244` | red-head `test_1025_page_contract.py:244` |
| `test_1025_a_render_that_raises_midway_keeps_the_previous_page` | red-head `test_1025_page_contract.py:760` | red-head `test_1025_page_contract.py:760` | red-head `test_1025_page_contract.py:760` |
| `test_1025_an_interrupt_during_the_render` | red-head `test_1025_page_contract.py:695` | red-head `test_1025_page_contract.py:695` | red-head `test_1025_page_contract.py:695` |
| `test_1025_both_archived_episodes_render_from_a_copied_dir_with_no_runs_base_store_or_checkout_and_the_bytes_do_not_depend_on_where` | red-content `test_1025_page_contract.py:507` | red-content `test_1025_page_contract.py:507` | red-content `test_1025_page_contract.py:507` |
| `test_1025_byte_identity_across_two_interpreter_processes` | green | green | green |
| `test_1025_cli_argument_names_an_existing_regular_file_not_a_directory` | red-content `test_1025_page_contract.py:348` | red-content `test_1025_page_contract.py:348` | red-content `test_1025_page_contract.py:348` |
| `test_1025_cli_invoked_with_no_positional_argument` | red-content `test_1025_page_contract.py:338` | red-content `test_1025_page_contract.py:338` | red-content `test_1025_page_contract.py:338` |
| `test_1025_draw_or_judge_yaml_record_is_rewritten_mid_render` | red-head `test_1025_page_contract.py:613` | red-head `test_1025_page_contract.py:613` | red-head `test_1025_page_contract.py:613` |
| `test_1025_episode_dir_given_through_a_symlink` | red-content `test_1025_page_contract.py:635` | red-content `test_1025_page_contract.py:635` | red-content `test_1025_page_contract.py:635` |
| `test_1025_family_yaml_has_invalid_yaml_syntax` | red-content `test_1025_page_contract.py:406` | red-content `test_1025_page_contract.py:406` | red-content `test_1025_page_contract.py:406` |
| `test_1025_family_yaml_is_a_directory_not_a_file` | red-content `test_1025_page_contract.py:406` | red-content `test_1025_page_contract.py:406` | red-content `test_1025_page_contract.py:406` |
| `test_1025_family_yaml_is_zero_bytes` | red-content `test_1025_page_contract.py:406` | red-content `test_1025_page_contract.py:406` | red-content `test_1025_page_contract.py:406` |
| `test_1025_family_yaml_top_level_document_is_a_list_not_a_mapping` | red-content `test_1025_page_contract.py:406` | red-content `test_1025_page_contract.py:406` | red-content `test_1025_page_contract.py:406` |
| `test_1025_held_teardown_fault_after_a_completed_grade` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_contract.py:291` |
| `test_1025_how_the_operator_learns_where_the_page_is` | green | green | green |
| `test_1025_judge_yaml_replaced_by_a_concurrent_re_grade_partway_through_one_render` | red-head `test_1025_page_contract.py:595` | red-head `test_1025_page_contract.py:595` | red-head `test_1025_page_contract.py:595` |
| `test_1025_questioner_or_staging_abort_leaves_a_partial_directory` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_contract.py:662` |
| `test_1025_relative_and_trailing_slash_arguments` | red-content `test_1025_page_contract.py:373` | red-content `test_1025_page_contract.py:373` | red-content `test_1025_page_contract.py:373` |
| `test_1025_render_episode_writes_learning_html_beside_judge_yaml_and_returns_its_path` | red-content `test_1025_page_contract.py:112` | red-content `test_1025_page_contract.py:113` | red-content `test_1025_page_contract.py:113` |
| `test_1025_repair_and_regrade_leaves_the_page_stale` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_contract.py:528` |
| `test_1025_review_rejected_episode_and_the_page` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_contract.py:271` |
| `test_1025_runs_base_and_episodes_base_env_vars_point_at_nonexistent_paths_during_render` | red-content `test_1025_page_contract.py:396` | red-content `test_1025_page_contract.py:396` | red-content `test_1025_page_contract.py:397` |
| `test_1025_standalone_render_of_a_live_episode` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_contract.py:729` |
| `test_1025_the_cli_exit_status_for_a_degraded_page` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_contract.py:320` |
| `test_1025_the_launcher_renders_the_page_after_the_judge_frame_with_all_six_steps_on_it` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_contract.py:208` |
| `test_1025_two_renders_in_flight_against_the_same_episode_dir` | red-content `test_1025_page_contract.py:579` | red-content `test_1025_page_contract.py:579` | red-content `test_1025_page_contract.py:579` |
| `test_1025_visualize_episode_cli_exits_zero_on_an_episode_dir_and_one_with_no_page_otherwise` | red-content `test_1025_page_contract.py:143` | red-content `test_1025_page_contract.py:143` | red-content `test_1025_page_contract.py:143` |
| `test_1025_a_malformed_record_versus_an_absent_one` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_records.py:440` |
| `test_1025_a_served_ledger_present_but_truncated` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_records.py:512` |
| `test_1025_a_torn_staging_record` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_records.py:459` |
| `test_1025_an_alias_planted_at_each_record_name` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_records.py:413` |
| `test_1025_an_unreadable_regular_file_at_a_record_name` | skipped | skipped | skipped |
| `test_1025_each_record_in_the_records_section_renders_as_absent_when_missing_and_its_content_when_present` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_records.py:120` |
| `test_1025_episode_root_provenance_json_is_a_directory` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_records.py:571` |
| `test_1025_grade_episode_reads_world_archive_through_the_same_screen_as_the_page` | green | green | green |
| `test_1025_grade_episode_still_grades_an_episode_whose_samples_yaml_is_malformed` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_records.py:773` |
| `test_1025_judge_render_reads_world_archive_through_the_same_screen_as_the_page` | green | green | green |
| `test_1025_judge_yaml_has_invalid_yaml_syntax` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_records.py:295` |
| `test_1025_malformed_samples_or_provenance_reads_as_absent` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_records.py:389` |
| `test_1025_markup_in_every_model_authored_field_renders_as_text_on_every_section` | red-content `test_1025_page_records.py:173` | red-content `test_1025_page_records.py:173` | red-content `test_1025_page_records.py:173` |
| `test_1025_markup_in_the_records_no_planted_field_covers` | red-content `test_1025_page_records.py:217` | red-content `test_1025_page_records.py:217` | red-content `test_1025_page_records.py:217` |
| `test_1025_non_ascii_and_control_characters_in_rendered_strings` | red-content `test_1025_page_records.py:234` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` |
| `test_1025_one_malformed_sidecar_record_sits_beside_otherwise_intact_ones` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_records.py:527` |
| `test_1025_review_yaml_cannot_be_read_as_the_expected_record` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_records.py:368` |
| `test_1025_review_yaml_is_present_but_its_worlds_key_is_absent` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_records.py:352` |
| `test_1025_the_episode_root_and_a_worlds_provenance_json_use_different_key_shapes_at_the_same_file_name` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_records.py:590` |
| `test_1025_the_four_baseline_entries_naming_this_page_as_their_reader_are_gone_and_the_lint_is_green` | green | green | green |
| `test_1025_the_new_modules_tree_reads_are_censused` | green | green | green |
| `test_1025_the_page_encodes_with_errors_replace_before_the_guarded_write` | red-content `test_1025_page_records.py:274` | red-content `test_1025_page_records.py:274` | red-content `test_1025_page_records.py:274` |
| `test_1025_the_page_module_reads_every_record_through_its_package_reader_spells_no_record_name_and_imports_no_private_helper` | red-other `test_1025_page_records.py:620` | red-other `test_1025_page_records.py:620` | red-other `test_1025_page_records.py:620` |
| `test_1025_the_root_stamp_reader_lives_in_the_record_names_home_beside_family_stamp_name` | green | green | green |
| `test_1025_timing_json_is_present_but_not_the_stageclock_record_shape` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_records.py:313` |
| `test_1025_timing_json_names_a_step_outside_the_steps_vocabulary` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_records.py:334` |
| `test_1025_a_comparator_trace_from_the_review_step` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` |
| `test_1025_a_framed_trace_row_carries_a_failure_field_instead_of_a_reply` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` |
| `test_1025_a_result_event_that_is_forged_or_misplaced` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_stages.py:583` |
| `test_1025_a_sibling_tool_trace_jsonls_final_row_is_not_a_result_event` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_stages.py:438` |
| `test_1025_a_steps_ended_at_sorts_before_its_started_at` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_stages.py:243` |
| `test_1025_a_symlinked_tool_trace_in_a_run_dir` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_stages.py:606` |
| `test_1025_a_trace_response_row_names_a_model_absent_from_the_pricing_table` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` |
| `test_1025_a_trace_whose_last_line_is_torn` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` |
| `test_1025_a_trace_with_a_request_row_and_no_response_row` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` |
| `test_1025_a_very_long_unbroken_token` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` |
| `test_1025_comparator_trace_present_but_empty` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_stages.py:527` |
| `test_1025_each_questioner_and_judge_trace_renders_a_labelled_block_family_first_with_the_framed_prompt_and_every_response_row` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` |
| `test_1025_judge_trace_stems_with_underscored_labels_and_two_digit_draws` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_stages.py:369` |
| `test_1025_questioner_request_rows_have_no_framed_file` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` |
| `test_1025_render_against_a_still_running_sibling_with_no_result_event_yet` | red-content `test_1025_page_stages.py:451` | red-content `test_1025_page_stages.py:451` | red-content `test_1025_page_stages.py:452` |
| `test_1025_response_rows_missing_usage_model_or_duration` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` |
| `test_1025_six_transcript_streams_and_one_set_of_controls` | red-content `test_1025_page_stages.py:540` | red-content `test_1025_page_stages.py:540` | red-content `test_1025_page_stages.py:540` |
| `test_1025_stage_costs_sum_response_row_usage_and_each_runs_result_event_and_a_run_with_no_trace_shows_no_cost_not_zero` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_stages.py:166` |
| `test_1025_the_runs_row_has_two_clocks` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_stages.py:276` |
| `test_1025_the_stage_table_has_one_row_per_step_runs_expanded_per_run_dir_wall_only_rows_and_a_total_that_says_what_it_excludes` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_stages.py:100` |
| `test_1025_timing_json_lists_the_same_step_twice_or_out_of_launch_order` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_stages.py:565` |
| `test_1025_trace_present_but_framed_absent` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` |
| `test_1025_trace_prompt_or_reply_contains_a_literal_pre_or_script_close_tag` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` |
| `test_1025_what_the_header_wall_covers` | red-content `_episode_1025.py:976` | red-content `_episode_1025.py:954` | red-content `test_1025_page_stages.py:261` |
| `test_1025_without_timing_json_the_axis_is_model_time_with_a_labelled_lower_bound_and_with_it_the_launchers_wall_per_step` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_stages.py:124` |
| `test_1025_a_draw_document_is_missing_its_findings_key_entirely` | red-content `test_1025_page_verdict.py:116` | red-content `test_1025_page_verdict.py:116` | red-content `test_1025_page_verdict.py:798` |
| `test_1025_a_draw_document_is_torn_mid_write` | red-content `test_1025_page_verdict.py:736` | red-content `test_1025_page_verdict.py:736` | red-content `test_1025_page_verdict.py:736` |
| `test_1025_a_draw_document_that_is_only_a_failure_reason` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_verdict.py:879` |
| `test_1025_a_finding_id_recorded_in_judge_yaml_names_a_world_draw_index_triple_absent_from_every_draw_document` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` |
| `test_1025_a_finding_row_carries_a_non_null_world_field_that_disagrees_with_its_directory` | red-content `test_1025_page_verdict.py:1165` | red-content `test_1025_page_verdict.py:1165` | red-content `test_1025_page_verdict.py:1165` |
| `test_1025_a_finding_that_is_not_a_mapping` | red-content `test_1025_page_verdict.py:116` | red-content `test_1025_page_verdict.py:116` | red-content `test_1025_page_verdict.py:865` |
| `test_1025_a_findings_disposition_reproduces_the_enqueues_partition_withheld_unqueueable_blocked_by_verdict_or_enqueued` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` |
| `test_1025_a_gradable_row_whose_draws_never_ran` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_verdict.py:1303` |
| `test_1025_a_not_graded_page_below_the_band` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_verdict.py:285` |
| `test_1025_a_not_graded_stamp_renders_its_reason_and_no_tiles_cards_or_findings_table` | red-content `test_1025_page_verdict.py:259` | red-content `test_1025_page_verdict.py:259` | red-content `test_1025_page_verdict.py:260` |
| `test_1025_a_world_drawn_twice_renders_both_draws_findings_once_each_in_numeric_draw_order_via_draws_on_disk` | red-content `test_1025_page_verdict.py:533` | red-content `test_1025_page_verdict.py:533` | red-content `test_1025_page_verdict.py:533` |
| `test_1025_a_world_finding_refused_for_citing_an_unavailable_sample` | red-content `test_1025_page_verdict.py:905` | red-content `test_1025_page_verdict.py:905` | red-content `test_1025_page_verdict.py:905` |
| `test_1025_a_worlds_row_mechanical_world_findings_entry_and_a_real_numeric_draw_coexist_for_the_same_world` | red-content `test_1025_page_verdict.py:1209` | red-content `test_1025_page_verdict.py:1209` | red-content `test_1025_page_verdict.py:1209` |
| `test_1025_an_episode_with_no_judge_yaml_still_renders_its_stages_and_worlds_and_says_there_is_no_grade_record` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_verdict.py:317` |
| `test_1025_an_episode_with_only_the_control` | red-content `test_1025_page_verdict.py:116` | red-content `test_1025_page_verdict.py:116` | red-content `test_1025_page_verdict.py:1329` |
| `test_1025_an_unqueueable_line_that_matches_no_rendered_finding` | red-content `_episode_1025.py:976` | red-content `_episode_1025.py:976` | red-content `test_1025_page_verdict.py:1247` |
| `test_1025_bucket_value_outside_the_closed_or_open_vocabularies` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` |
| `test_1025_draw_directory_holds_a_file_stem_written_with_a_non_ascii_digit` | red-content `test_1025_page_verdict.py:1148` | red-content `test_1025_page_verdict.py:1148` | red-content `test_1025_page_verdict.py:1148` |
| `test_1025_draw_directory_holds_both_1_yaml_and_01_yaml` | red-content `test_1025_page_verdict.py:1132` | red-content `test_1025_page_verdict.py:1132` | red-content `test_1025_page_verdict.py:1132` |
| `test_1025_draw_documents_exist_but_judge_yaml_does_not` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_verdict.py:340` |
| `test_1025_draw_index_beyond_the_recorded_completed_draw_count` | red-content `test_1025_page_verdict.py:824` | red-content `test_1025_page_verdict.py:824` | red-content `test_1025_page_verdict.py:824` |
| `test_1025_every_finding_across_per_draw_docs_family_draws_and_mechanical_rows_renders_exactly_once_keyed_world_draw_index` | red-content `test_1025_page_verdict.py:366` | red-content `test_1025_page_verdict.py:366` | red-content `test_1025_page_verdict.py:366` |
| `test_1025_family_call_faulted_after_writing_a_draw` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_verdict.py:1279` |
| `test_1025_family_drawn_several_times_with_a_dissenting_draw` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_verdict.py:968` |
| `test_1025_findings_render_one_table_per_addressee_with_the_seven_columns_family_rows_at_family_level_and_dropped_counts_per_draw` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` |
| `test_1025_identical_findings_under_two_draws` | red-content `test_1025_page_verdict.py:1263` | red-content `test_1025_page_verdict.py:1263` | red-content `test_1025_page_verdict.py:1263` |
| `test_1025_judge_yaml_carries_a_top_level_field_this_readers_schema_has_never_seen` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_verdict.py:1111` |
| `test_1025_judge_yaml_is_a_symlink_whose_target_is_a_different_episodes_judge_yaml` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_verdict.py:1078` |
| `test_1025_judge_yaml_is_present_with_an_empty_worlds_array_and_no_not_graded_stamp` | red-content `test_1025_page_verdict.py:116` | red-content `test_1025_page_verdict.py:116` | red-content `test_1025_page_verdict.py:1099` |
| `test_1025_malformed_replies_and_gaps_in_draw_numbering` | red-content `test_1025_page_verdict.py:1186` | red-content `test_1025_page_verdict.py:1186` | red-content `test_1025_page_verdict.py:1186` |
| `test_1025_manifest_fields_the_slot_bindings_never_name` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_verdict.py:994` |
| `test_1025_no_hand_written_sentence_from_the_artifact_appears_while_every_templated_count_sentence_does` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_verdict.py:614` |
| `test_1025_one_card_per_graded_world_with_declared_to_verdict_reason_or_bucket_heading_chips_and_a_footer_linking_its_findings_group` | red-content `test_1025_page_verdict.py:579` | red-content `test_1025_page_verdict.py:579` | red-content `test_1025_page_verdict.py:579` |
| `test_1025_one_draw_document_is_a_symlink_to_a_file_outside_the_episode` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_verdict.py:757` |
| `test_1025_queue_accounting_lists_per_queue_rows_destination_as_recorded_withheld_reasons_unqueueable_malformed_and_dropped_counts` | red-content `test_1025_page_verdict.py:555` | red-content `test_1025_page_verdict.py:555` | red-content `test_1025_page_verdict.py:557` |
| `test_1025_record_fields_no_slot_binds` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` |
| `test_1025_recorded_finding_ids_carry_a_different_episode_prefix` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` |
| `test_1025_render_reflects_a_not_graded_to_graded_transition_across_two_calls` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_verdict.py:1364` |
| `test_1025_render_when_family_judge_dir_exists_but_is_empty` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_verdict.py:1348` |
| `test_1025_subject_field_holds_a_value_outside_defender_and_world` | red-content `test_1025_page_verdict.py:842` | red-content `test_1025_page_verdict.py:842` | red-content `test_1025_page_verdict.py:842` |
| `test_1025_the_badge_is_family_outcome_falling_back_to_verdict_word_and_the_meta_line_carries_episode_outcome_and_verdict_word` | red-content `test_1025_page_verdict.py:197` | red-content `test_1025_page_verdict.py:197` | red-content `test_1025_page_verdict.py:198` |
| `test_1025_the_episode_level_verdicts_justification` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_verdict.py:924` |
| `test_1025_the_lede_lists_family_draw_findings_verbatim_grouped_by_draw_or_opens_with_the_templated_line_when_there_is_no_family_draw` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_verdict.py:162` |
| `test_1025_the_same_finding_id_string_appears_in_two_different_draw_documents` | red-content `test_1025_page_verdict.py:812` | red-content `test_1025_page_verdict.py:812` | red-content `test_1025_page_verdict.py:812` |
| `test_1025_the_verdict_tile_carries_measuring_contrasting_and_verdict_equals_declared_counts_on_both_archives` | red-content `test_1025_page_verdict.py:116` | red-content `test_1025_page_verdict.py:116` | red-content `test_1025_page_verdict.py:216` |
| `test_1025_tiles_two_to_four_carry_measuring_of_graded_with_reasons_queued_of_total_split_and_cost_with_the_labelled_lower_bound` | red-content `test_1025_page_verdict.py:116` | red-content `test_1025_page_verdict.py:116` | red-content `test_1025_page_verdict.py:235` |
| `test_1025_top_level_enqueue_counts_disagree_with_the_rows_the_page_walks` | red-content `_episode_1025.py:976` | red-content `_episode_1025.py:976` | red-content `test_1025_page_verdict.py:687` |
| `test_1025_unqueueable_reason_text_contains_the_page_join_delimiter` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` |
| `test_1025_verdict_word_outside_the_five_known_values` | red-content `test_1025_page_verdict.py:116` | red-content `test_1025_page_verdict.py:116` | red-content `test_1025_page_verdict.py:1033` |
| `test_1025_withheld_cross_check_fails` | red-content `_episode_1025.py:976` | red-content `_episode_1025.py:976` | red-content `test_1025_page_verdict.py:707` |
| `test_1025_withheld_findings_are_grouped_under_their_reason_apart_from_enqueued_rows_and_never_worded_as_rejected` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` |
| `test_1025_withheld_reason_outside_the_four_known_values` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` |
| `test_1025_a_bucket_or_reason_word_used_as_an_attribute_value` | red-content `test_1025_page_worlds.py:517` | red-content `test_1025_page_worlds.py:517` | red-content `test_1025_page_worlds.py:517` |
| `test_1025_a_declared_world_with_no_run_directory` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` |
| `test_1025_a_gather_summary_stem_that_is_hostile` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_worlds.py:492` |
| `test_1025_a_judge_trace_for_a_world_or_draw_the_record_lacks` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_worlds.py:655` |
| `test_1025_a_lead_id_that_names_no_single_file_reads_nothing_and_renders_the_guards_sentence` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_worlds.py:365` |
| `test_1025_a_row_without_has_refused_gets_the_caveat_only_on_the_not_doctored_branch_and_never_an_invented_value` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_worlds.py:215` |
| `test_1025_a_run_dir_with_a_result_event_and_no_runtime_html` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_worlds.py:726` |
| `test_1025_a_run_directory_symlink_or_dir_pointer_naming_a_symlinked_final_component` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_worlds.py:943` |
| `test_1025_a_run_directory_whose_name_is_not_episode_dash_label` | red-content `test_1025_page_worlds.py:678` | red-content `test_1025_page_worlds.py:678` | red-content `test_1025_page_worlds.py:678` |
| `test_1025_a_sibling_process_exited_non_zero` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_worlds.py:1102` |
| `test_1025_a_world_section_is_not_graded_ungradable_with_its_reason_or_graded_and_never_confuses_the_three` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_worlds.py:157` |
| `test_1025_a_world_that_ran_but_was_never_archived` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` |
| `test_1025_alert_fields_reach_the_header_frame` | red-content `_episode_1025.py:976` | red-content `test_1025_page_worlds.py:1056` | red-content `test_1025_page_worlds.py:1056` |
| `test_1025_axis_text_engineered_to_read_as_more_of_the_templated_sentence` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_worlds.py:535` |
| `test_1025_each_world_links_to_runs_episode_world_runtime_html_relatively_and_the_run_dir_pointer_is_never_the_source` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_worlds.py:279` |
| `test_1025_every_step_in_steps_order_and_every_directory_under_runs_has_its_section_the_control_included` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_worlds.py:134` |
| `test_1025_family_yaml_declares_two_worlds_under_the_same_label` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_worlds.py:556` |
| `test_1025_gather_summaries_holds_a_file_that_is_not_markdown` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_worlds.py:963` |
| `test_1025_headings_carry_substituted_counts_the_worlds_guide_uses_each_axis_verbatim_and_the_nav_iterates_the_same_sets_as_the_sections` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_worlds.py:309` |
| `test_1025_investigation_md_is_present_but_unreadable` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_worlds.py:974` |
| `test_1025_judge_yaml_worlds_row_names_a_label_absent_from_family_yaml_and_runs` | red-content `test_1025_page_worlds.py:573` | red-content `test_1025_page_worlds.py:573` | red-content `test_1025_page_worlds.py:573` |
| `test_1025_leftover_draw_documents_under_a_world_the_record_excludes` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` |
| `test_1025_manifest_labels_as_frame_slots_on_an_ungated_manifest` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_worlds.py:449` |
| `test_1025_markup_in_lead_params_raw_command_and_resolutions` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_worlds.py:1085` |
| `test_1025_no_worlds_alert_json_carries_an_alert_id` | red-content `_episode_1025.py:976` | red-content `test_1025_page_worlds.py:989` | red-content `test_1025_page_worlds.py:989` |
| `test_1025_partial_copy_missing_served_or_worlds_or_wire_logs` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_worlds.py:1123` |
| `test_1025_per_world_leads_are_referenced_leads_union_gather_summary_stems_with_their_chains_and_exclude_pre_branch_leads` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_worlds.py:337` |
| `test_1025_phantom_family_draw_on_an_episode_with_no_family_judge_call` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_worlds.py:642` |
| `test_1025_phantom_world_judge_dir_absent_from_manifest_and_from_runs` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_worlds.py:625` |
| `test_1025_record_declared_and_manifest_declared_disagree` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_worlds.py:778` |
| `test_1025_render_against_a_world_archive_mid_copy` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_worlds.py:892` |
| `test_1025_render_before_a_worlds_scrub_verdict_sidecar_is_written` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_worlds.py:813` |
| `test_1025_render_when_a_graded_world_has_no_matching_runs_dir` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_worlds.py:712` |
| `test_1025_review_record_lacks_a_worlds_block_for_a_world` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_worlds.py:912` |
| `test_1025_runs_pruned_after_the_grade` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_worlds.py:739` |
| `test_1025_symlink_planted_at_a_leaf_file_the_page_reads_inside_a_world` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_worlds.py:1005` |
| `test_1025_the_artifacts_anchor_ids_exist_and_every_nav_href_resolves_to_an_id_on_the_page` | red-content `test_1025_page_worlds.py:382` | red-content `test_1025_page_worlds.py:382` | red-content `test_1025_page_worlds.py:382` |
| `test_1025_the_control_is_identified_how` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_worlds.py:852` |
| `test_1025_the_control_worlds_chips_and_review_block` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_worlds.py:799` |
| `test_1025_the_header_names_the_episode_alert_rule_source_run_and_branch_point_knobs_and_lessons_commit_never_defender_run` | red-content `test_1025_page_worlds.py:409` | red-content `test_1025_page_worlds.py:412` | red-content `test_1025_page_worlds.py:412` |
| `test_1025_the_ladder_block_walks_the_stored_flags_in_ladder_order_and_shows_the_stored_bucket_even_when_the_flags_would_not_derive_it` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_worlds.py:189` |
| `test_1025_two_world_labels_differ_only_by_case_or_a_lookalike_character` | red-content `test_1025_page_worlds.py:827` | red-content `test_1025_page_worlds.py:827` | red-content `test_1025_page_worlds.py:827` |
| `test_1025_ungradable_rows_from_the_early_tiers_carry_no_flags` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_worlds.py:759` |
| `test_1025_ungradable_world_carries_a_populated_judge_directory` | red-content `test_1025_page_worlds.py:588` | red-content `test_1025_page_worlds.py:588` | red-content `test_1025_page_worlds.py:588` |
| `test_1025_world_chips_are_the_named_fields_say_unrecorded_when_absent_and_sit_beside_the_ladder_not_instead_of_it` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_worlds.py:243` |
| `test_1025_world_or_lead_directory_name_carries_attribute_or_tag_breaking_characters` | red-content `_episode_1025.py:954` | red-content `_episode_1025.py:954` | red-content `test_1025_page_worlds.py:474` |
