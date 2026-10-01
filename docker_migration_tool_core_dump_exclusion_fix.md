# Docker Migration Tool Core Dump Exclusion Fix

## 1. Summary

広すぎる `core.*` globを除外policyから撤去し、Linux core dump専用の `core_dump` 判定（候補名 + 通常ファイル + ELF header + `ET_CORE`）へ置き換えた。`core.py` 等の通常sourceは名前が似ていても必ず残す。判定できないファイルは保持側へfail-safeする。

監査用に、実際に除外した全ファイルを `workspace/EXCLUDED_FILES.json` に記録する（P1）。

さらに、archiveに採用した全ファイルの個別SHA-256を `workspace/src.sha256` に記録する（P2）。import時に復元結果と照合し、欠落またはhash不一致があれば具体的なpathを表示して `workspace_restored` を `passed=False` にする。

P0/P1は既存commit `4e8fa46`（"fixed Bugs"）でrepositoryに入っていた。今回はその実装をコードと調査レポートに照らして再確認し、不足していたregression testとP2を追加した。

## 2. Incident

SO101 workspaceをexportした際、正常なPython source `src/so101_demo/core.py` がmigration bundleから欠落した（調査レポートのCASE B）。

- release manifest `/opt/release/source.sha256`: 176ファイル
- release image `/workspace/src/so101_demo/core.py`: 存在し、SHA256はmanifestと一致
- bundle `workspace/src.tar.zst`: 175ファイル
- 差分（manifest − archive）: `./so101_demo/core.py` の1件のみ

## 3. Root Cause

- `DEFAULT_WORKSPACE_EXCLUDES`（`inspect/workspace.py`）にcore dump除外を意図した `core.*` が入っていた。
- `_pattern_matches_relative()`（`utils/filesystem.py`）は、wildcard patternを相対pathとbasenameの両方に `fnmatch` で適用する。
- そのため `core.*` が `core.py`、`core.cpp`、`core.launch.py` 等のbasenameにも一致した。
- `EXCLUDED.txt` にはpatternしか記録されず、10MB未満のファイルはlarge-file監査にも出ない。結果として `core.py` の除外がどこにも記録されず、silentに失われた。

## 4. Original Behavior

- `core.12345`（本物のcore dump）と `core.py`（source）を区別せずに除外していた。
- 実際に除外されたファイルの一覧が存在しなかった。
- importはarchiveにあるものを展開するだけで、archive自体のSHA256以外にファイル単位の完全性確認がなかった。

## 5. Design Decision

- **filename candidate**: `core` または `core.<数字>` に完全一致する名前だけを候補にする（`re.fullmatch(r"core(?:\.[0-9]+)?")`）。`core.py` は候補にもならない。
- **regular file**: `lstat` で通常ファイルを確認する。symlinkは辿らず、FIFO/device等は除外しない。
- **ELF magic + type**: 先頭18byteを読み、`\x7fELF` と `EI_DATA`（endian）に応じた `e_type == ET_CORE (4)` を確認する。ELF実行ファイルやshared object（`ET_EXEC`/`ET_DYN`）は除外しない。
- **fail-safe**: 読取不能（`OSError`）、18byte未満、endian不明、ELF以外は、すべて除外しない。
- **custom `kernel.core_pattern`**: 任意の名前を推測で除外しない。名前候補に当たらない限り保持する（preservation優先）。
- policy上は `core_dump` というsentinel名で表す。相対path matcher（`matched_exclude_pattern_for_relative`）は実体を見られないため、常に「除外しない」を返す。実ファイルを扱う `matched_exclude_pattern` / `is_excluded` だけが `is_core_dump()` を呼ぶ。拡張子denylistには依存しない。

## 6. Files Changed

既存commit `4e8fa46`（P0/P1）:
- `src/docker_migration_tool/inspect/workspace.py`: `core.*` を `core_dump` に置換。large-file判定に実pathを渡す。
- `src/docker_migration_tool/utils/filesystem.py`: `is_core_dump()`。`create_archive()` が除外ファイル一覧を返す。
- `src/docker_migration_tool/export/bundle.py`: `EXCLUDED_FILES.json` の生成とMANIFEST checksum登録。
- `tests/test_workspace_exclusion.py`、`README.md`、`README_ja.md`。

今回の変更（未commit）:
- `src/docker_migration_tool/utils/filesystem.py`: `create_archive(..., included_files=)`、`write_file_manifest()`、`read_file_manifest()`、`verify_file_manifest()`。
- `src/docker_migration_tool/export/bundle.py`: `workspace/src.sha256` を生成し、MANIFEST checksumに登録。
- `src/docker_migration_tool/importers/restore.py`: 復元後のファイル単位照合と、旧bundle向けの互換モード。
- `tests/test_workspace_exclusion.py`: big-endian core、短いheader、SO101のincident path、zstd archive listing、監査がmetadataのみであることのテストを追加。fake `create_archive` のsignatureを更新。
- `tests/test_workspace_file_manifest.py`（新規）: P2のテスト。
- `README.md`、`README_ja.md`: `src.sha256` と、core系の名前を持つsourceを保持することを追記。
- 本レポート。

## 7. Core Dump Detection

| fixture | 結果 |
|---|---|
| `core`（ELF LE `ET_CORE`） | 除外 (`core_dump`) |
| `core.12345`（ELF LE `ET_CORE`） | 除外 |
| `core.433778`（ELF BE `ET_CORE`） | 除外 |
| `core`（ELF `ET_EXEC`） | 保持 |
| `core.12345`（text） | 保持（false-positive test） |
| `core.12345`（`\x7fELF` のみ、4byte） | 保持 |
| `core.12345` → symlink to ELF core | 保持 |
| `core.12345`（open時にPermissionError） | 保持 |

## 8. Source Preservation

`core.py` `core.cpp` `core.cc` `core.c` `core.h` `core.hpp` `core.rs` `core.go` `core.java` `core.js` `core.ts` `core.md` `core.txt` `core.yaml` `core.yml` `core.json` `core.xml` `core.launch.py` `core.sh` の全19種について、次の2つを確認した。

- `matched_exclude_pattern_for_relative()` が `None` を返す。
- `is_excluded()` が `False` を返す。

archive integration testでは次を確認した。

- 非圧縮tar: `core.py`、`core.cpp`、`core.hpp`、`core.md`、`core.yaml`、`core.launch.py` と text の `core.67890` が含まれる。ELFの `core` と `core.12345` は含まれない。
- 実export形式（`src.tar.zst`）: `example_pkg/core.py` と `core.cpp` が含まれ、`core.12345`（ELF core）は含まれない。tar listingで確認した。

## 9. Exclusion Audit

`workspace/EXCLUDED_FILES.json`:

```json
{
  "schema_version": "1.0.0",
  "files": [
    {"path": "example_pkg/core.12345", "size": 18,
     "excluded_by": "core_dump", "reason": "ELF core dump"},
    {"path": "example_pkg/build/small.bin", "size": 1,
     "excluded_by": "**/build", "reason": "Policy: **/build"}
  ]
}
```

- サイズに関係なく、除外された全ファイルを記録する。除外directory配下の各ファイルも含む。
- 記録するのは `path`/`size`/`excluded_by`/`reason` のみで、内容は記録しない。`.env` fixtureの値がJSONに現れないことをテストで確認した。
- このJSONのSHA-256は `MANIFEST.json` の `checksums` に登録され、preflightとverifyで改ざんを検出する。
- 従来の `EXCLUDED.txt`（policy一覧）と `EXCLUDED_LARGE_FILES.json` は維持した。

## 10. Workspace Integrity Manifest

`workspace/src.sha256` は GNU `sha256sum` 形式で、pathは `src` からの相対pathである。

- **内容**: `create_archive()` がarchiveへ実際に追加した通常ファイルだけを記録する。excludeされた `__pycache__`、`build`、`install`、`log`、core dump、`.env` 等の生成・credentialファイルは載らないため、欠落扱いにならない。
- **改ざん検出**: SHA-256を `MANIFEST.json` の `checksums` に登録する。新bundleでこのファイルが消された場合はpreflightの `Missing file` で失敗する。
- **path escape**: backslashと改行を含むpathはGNU方式でescapeする。`sha256sum -c` で検証可能なことを確認した。読込時は `..`、絶対path、不正なhashを拒否する。
- **import**: `safe_extract_archive()` の後に全entryを照合する。missing（ファイルがない、または通常ファイルでない）とhash mismatchを個別に `log_error` で表示する。そのうえで `workspace_restored` を `passed=False, status=error`（`details.missing` / `details.mismatched`）にして、importを `failed_stage=workspace_restore` で停止する。zstdの異常などによる不完全な展開もmissingとして検出される。
- **照合しないもの**: manifestに無い追加ファイル（restore先の既存ファイル）は報告しない。symlinkはhash対象外。

## 11. Backward Compatibility

- **旧bundle**（MANIFEST `checksums` に `workspace/src.sha256` がない）: 従来どおり復元する。`workspace_restored` は `passed=True, status=warning`（"legacy bundle: no per-file manifest"）とする。`EXCLUDED_FILES.json` がないことも拒否理由にしない。
- **新bundle**: `src.sha256` がchecksumに登録されているため、その存在、checksum一致、復元後の照合が必須になる。
- **共通**: 既存のsecurity metadata要件（unsafe legacy bundleの拒否など）は変更していない。`create_archive()` の追加引数はoptionalで、戻り値も従来どおり。

## 12. Security Regression Check

clean parent image proof、runtime snapshot非export、image config/history secret scan、final filesystem secret scan、`docker save` 全layer secret scan、bundle checksum、safe archive extraction、credential/generated file除外のコードには手を入れていない。

除外policyはテストで固定した。

- `**/__pycache__`、`**/build`、`**/install`、`**/log`、`core_dump`、`*.jsonl`
- `.env`、`docker-compose.override.yml`、`compose.generated.yml`、`.docker.xauth`、`robotics-xauthority`

`core.*` がpolicyに含まれないことも明示的にassertしている。新しい監査とmanifestにはファイル内容を書かない。

## 13. Tests

`.venv/bin/python -m pytest -o addopts="" -q`

| | 件数 |
|---|---|
| 今回の作業開始時（commit `4e8fa46` 時点） | 338 passed |
| 追加: `test_workspace_exclusion.py` | +5 |
| 追加: `test_workspace_file_manifest.py` | +15 |
| 最終 | **358 passed / 0 failed** |

参考: P0/P1導入前は296 tests。`4e8fa46` で +26（core dump関連）と compose build portability のテストが加わり、338件になっていた。

既存テスト `core.12345 が core.* に一致` と `policyに "core.*" が含まれる` は削除していない。次の新仕様へ置き換え済みである。

- `core.*` がpolicyに含まれないこと
- 相対pathだけでは `core.12345` を除外しないこと
- 実ファイルのELF coreは除外されること

## 14. SO101 Regression Verification

対象 `~/my_docker_ws/SO101_YOLO_MoveIt_v13/src` は読み取り専用で扱った。作業前後の全ファイルのsha256一覧が一致することを確認している。

- `matched_exclude_pattern_for_relative("so101_demo/core.py")` → `None`
- `is_excluded(.../so101_demo/core.py)` → `False`
- `/tmp` 配下で同じpolicyにより `src.tar.zst` を生成した:
  - tar listingの通常ファイルは **176件**（release manifestと同数）で、`so101_demo/core.py` が含まれる。
  - 除外は13件で、すべて `**/__pycache__` の `.pyc`。`core.py` は除外一覧にない。
  - `src.sha256` は176 entries。
  - 一時展開に対する `verify_file_manifest()` → missing 0、mismatch 0。
- 一時artifactは削除済み。

`~/migration_bundles/` 配下は、作業前後でファイル一覧・サイズ・mtimeが一致することを確認した（未変更）。release imageとgitには触れていない（commit/pushなし）。

## 15. Remaining Limitations

- custom `kernel.core_pattern`（例: `core-%e-%p-%t`）の名前はcore dumpとして除外しない（保持側）。不要な大容量ファイルが混入する可能性はあるが、large-file一覧で可視化される。
- ELF以外の形式のcore dump（systemd-coredumpの圧縮形式など）は検出しない。通常は `src` 外に保存される。
- `src.sha256` は通常ファイルのみが対象で、symlinkのtargetや空directoryは照合しない。
- hash計算と `tar.add` は別々の読み込みのため、export中にsourceが変更されるとimport時にmismatchとして検出される（失敗側に倒れる）。
- 既存bundle（例: `SO101_YOLO_MoveIt_v13_migration_bundle_20260923`）は `core.py` を欠いたままである。immutable artifactとして修正していないため、必要なら修正後のtoolで再exportする。

## 16. GitHub repositoryへの反映（2026-10-01）

本修正とworkspace単位の `src.sha256` 検証を、cloneしたGitHub repositoryへ反映した。
GitHub側に既存の `env.sh` 正規化・runtime image整合性チェック・portable config
checksumは保持した。統合後の全testは370件passした。commit/pushは行っていない。
