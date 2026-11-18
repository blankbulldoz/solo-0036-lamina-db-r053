# LaminaDB durability fault matrix

- binary: `/workspace/bin/laminad` sha256 `f97c55a62590ef856cc5cb1ef9e09f58d62fb87b897b70745cc8ff0ca8f61e1d`
- tracer: `/workspace/verification/tracer/laminad-fault` sha256 `d4e101622354eec13b95c62a0a653e801f4bea9dc4a8f60159df4393453bb954`
- run: `2026-11-18T07:50:41`

| case | path | boundary | confirmed | exact | repeat | classification | detail |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `commit-baseline-ack-then-kill` | commit-confirmation | - | yes | yes | consistent | **confirmed_and_persisted** | 200 recorded and payload present after recovery |
| `commit-kill-in-write` | commit-confirmation | kill-in:1:write | no | yes | consistent | **unconfirmed_absent** | no 200 and payload absent (permitted) |
| `commit-kill-after-write` | commit-confirmation | kill-after:1:write | no | yes | consistent | **unconfirmed_persisted** | no 200 but bytes survived (permitted; client cannot know) |
| `commit-kill-in-fsync` | commit-confirmation | kill-in:1:fsync | no | yes | consistent | **unconfirmed_persisted** | no 200 but bytes survived (permitted; client cannot know) |
| `commit-kill-after-fsync` | commit-confirmation | kill-after:1:fsync | no | yes | consistent | **unconfirmed_persisted** | no 200 but bytes survived (permitted; client cannot know) |
| `commit-abort-after-fsync` | commit-confirmation | abort-after:1:fsync | yes | no (racy) | INCONSISTENT | **confirmed_and_persisted** | 200 recorded and payload present after recovery |
| `commit-eio-at-fsync` | commit-confirmation | eio-after:1:fsync | no | yes | consistent | **unconfirmed_persisted** | no 200 but bytes survived (permitted; client cannot know) |
| `commit-corrupt-after-write` | commit-confirmation | kill-after:1:write | no | yes | consistent | **must_refuse** | journal invalid: crc mismatch at offset 1031 (frame 4) |
| `commit-torn-after-write` | commit-confirmation | torn-after:1:write | no | yes | consistent | **unconfirmed_absent** | no 200 and payload absent (permitted) |
| `commit-multi-frame-after-write` | commit-confirmation | kill-after:1:write | no | yes | consistent | **unconfirmed_persisted** | no 200 but bytes survived (permitted; client cannot know) |
| `checkpoint-baseline-ack-then-kill` | checkpoint-replacement | - | yes | yes | consistent | **confirmed_and_recovered** | clean recovery |
| `checkpoint-kill-after-temp-fsync` | checkpoint-replacement | kill-after:1:fsync | no | yes | consistent | **recovered** | clean recovery |
| `checkpoint-kill-in-rename` | checkpoint-replacement | kill-in:1:rename | no | yes | consistent | **recovered** | clean recovery |
| `checkpoint-kill-after-rename` | checkpoint-replacement | kill-after:1:rename | no | yes | consistent | **recovered** | clean recovery |
| `checkpoint-kill-after-dir-fsync` | checkpoint-replacement | kill-after:2:fsync | no | yes | consistent | **recovered** | clean recovery |
| `checkpoint-corrupt-after-rename` | checkpoint-replacement | kill-after:1:rename | no | yes | consistent | **refused_after_unconfirmed_checkpoint** | checkpoint invalid: envelope json: 'utf-8' codec can't decode byte 0xc5 in position 534: invalid continuation byte |
| `checkpoint-kill-after-unlink-temp` | checkpoint-replacement | kill-after:1:unlink | no | yes | consistent | **recovered** | clean recovery |
| `checkpoint-twice-kill-in-second-rename` | checkpoint-replacement | kill-in:2:rename | no | yes | consistent | **recovered** | clean recovery |
| `backup-frozen-while-source-writes` | backup-install | - | - | yes | consistent | **backup_frozen_and_source_recoverable** |  |
| `restore-kill-in-journal-header-write` | restore-install | kill-in:1:write | - | yes | consistent | **restore_not_installed** | zero-length journal and no checkpoint; the directory can start as a fresh database but contains none of the backup |
| `restore-kill-after-journal-header-fsync` | restore-install | kill-after:1:fsync | - | yes | consistent | **restore_left_refusable_state** | journal requires checkpoint at base 3, but none is installed |
| `restore-kill-in-image-write` | restore-install | kill-in:2:write | - | yes | consistent | **restore_left_refusable_state** | journal requires checkpoint at base 3, but none is installed |
| `restore-kill-after-image-fsync` | restore-install | kill-after:3:fsync | - | yes | consistent | **restore_left_refusable_state** | journal requires checkpoint at base 3, but none is installed |
| `restore-kill-after-rename` | restore-install | kill-after:1:rename | - | yes | consistent | **restore_complete** | installed image exposes exactly the source rows |
| `restore-corrupt-before-install` | restore-install | kill-after:1:rename | - | yes | consistent | **restore_left_refusable_state** | checkpoint invalid: envelope json: 'utf-8' codec can't decode byte 0x82 in position 408: invalid start byte |
| `restore-tampered-digest` | restore-install | - | - | yes | consistent | **restore_aborted_cleanly** | restore made no directory; source backup untouched |
| `corrupt-journal-crc-flip` | corruption-rejection | - | - | yes | consistent | **refused_as_required** | corruption rejected at startup, as the format requires |
| `corrupt-journal-length-zero` | corruption-rejection | - | - | yes | consistent | **refused_as_required** | corruption rejected at startup, as the format requires |
| `corrupt-journal-sequence-gap` | corruption-rejection | - | - | yes | consistent | **refused_as_required** | corruption rejected at startup, as the format requires |
| `corrupt-journal-header-truncated` | corruption-rejection | - | - | yes | consistent | **refused_as_required** | corruption rejected at startup, as the format requires |
| `corrupt-journal-base-ahead` | corruption-rejection | - | - | yes | consistent | **refused_as_required** | corruption rejected at startup, as the format requires |
| `corrupt-checkpoint-digest-mismatch` | corruption-rejection | - | - | yes | consistent | **refused_as_required** | corruption rejected at startup, as the format requires |
| `corrupt-checkpoint-row-type` | corruption-rejection | - | - | yes | consistent | **refused_as_required** | corruption rejected at startup, as the format requires |
| `corrupt-checkpoint-version-order` | corruption-rejection | - | - | yes | consistent | **refused_as_required** | corruption rejected at startup, as the format requires |
| `corrupt-checkpoint-unknown-relation` | corruption-rejection | - | - | yes | consistent | **refused_as_required** | corruption rejected at startup, as the format requires |
| `corrupt-checkpoint-catalog-sequence` | corruption-rejection | - | - | yes | consistent | **refused_as_required** | corruption rejected at startup, as the format requires |
| `corrupt-checkpoint-unique-violation` | corruption-rejection | - | - | yes | consistent | **refused_as_required** | corruption rejected at startup, as the format requires |
| `corrupt-journal-tail-garbage` | corruption-rejection | - | - | yes | consistent | **accepted_cleanly** | journal tail of 3 bytes will be truncated |
