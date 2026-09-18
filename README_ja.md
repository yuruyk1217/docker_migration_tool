# docker-migration-tool

English version: [README.md](README.md)

Docker ベースの ROS 2 開発環境を、別の Linux マシンへ移行するためのツールです。
image、workspace、Git の状態、パッケージ manifest、ホスト固有設定をまとめて運びつつ、
既知の credential が bundle に混入しないように設計されています。

## 概要

`docker-migration-tool` は、稼働中の開発コンテナを調査し、持ち出して安全な image を
「証明」してから、再現可能な情報だけを自己記述的な bundle ディレクトリに固めます。
移行先ではその bundle を展開して環境を復元します。

ホスト固有の値（UID/GID、`DISPLAY`、デバイスのグループ ID、X11 cookie、生成済みの
compose ファイルなど）はコピーせず、移行先で再生成します。credential は意図的に
持ち出しません。

実体は Python パッケージ 1 つと、`docker-migration` CLI（`inspect` / `export` /
`import` / `verify` / `bundle-info` の 5 サブコマンド）です。

```
source machine                     bundle directory                target machine
──────────────                     ────────────────                ──────────────
running container   ──inspect──▶   MANIFEST.json                   docker load
clean parent image  ──export───▶   docker/image/base-image.tar  ──▶ workspace extract
workspace src                      workspace/src.tar.zst        ──▶ config regenerate
git + package state                git/, packages/              ──▶ dependency install
host + hardware facts              host/, hardware/             ──▶ compared, not copied
```

## クイックスタート

はじめて使う場合は、ここだけ読めば移行を一通り実行できます。以下では、いま
コンテナが動いているマシンを「マシン A」（移行元）、新しく環境を作るマシンを
「マシン B」（移行先）と呼びます。手順 4 までがマシン A、手順 5 以降がマシン B での
作業です。

`my-ros-container` は自分のコンテナ名に、`~/ros/my_workspace` はマシン B 上で
workspace を置きたいパスに読み替えてください。

### 0. 両方のマシンにインストールする

```bash
git clone <your-remote-url> docker-migration-tool
cd docker-migration-tool
pip install -e .

docker-migration --version        # CLI が PATH に入ったかの確認
```

マシン A には `docker`、`docker compose` プラグイン、`zstd`、`git` が必要です。
マシン B には `docker` と `zstd` が必要です。また、マシン B には 60 GB 以上の空き容量を
確保してください（bundle と load 後の image の両方が入る必要があります）。

### 1. コンテナ名を調べる（マシン A）

対象のコンテナは **起動している** 必要があります。稼働中の設定を読み取るためです。

```bash
docker ps --format '{{.Names}}\t{{.Image}}'
```

1 列目に出てくる名前が、以降で指定するコンテナ名です。

### 2. まず確認する: `inspect`（マシン A）

```bash
docker-migration inspect --container my-ros-container
```

このコマンドは読み取りだけを行い、ファイルの書き出しも Docker の状態変更もしません。
出力の最終行を確認してください。

- `Clean parent image proven - export is possible` → そのまま次へ進めます。
- `Clean parent image NOT proven - cannot export` → ここで止まります。持ち出して
  安全な image を証明できていないため、export は拒否されます。出力には却下した候補と
  その理由が並びます（よくある原因は、コンテナが `docker commit` の snapshot から
  起動していて、その base image がマシン上に残っていないケースです。base image を
  pull または再ビルドしてから再実行してください）。

レポート全体をあとで読みたい場合は `--output inspection.json` を付けます。

### 3. 予行演習する: `export --dry-run`（マシン A）

```bash
docker-migration export --container my-ros-container --dry-run
```

dry-run は何も書き出しませんが、4 つの security gate のうち 3 つは実際に実行されます。
つまり、問題はここで表に出ます。`config_metadata_scan: passed` と
`final_filesystem_scan: passed` が出ていることを確認してください。
`layer_scan: skipped_dry_run` は正常です。この gate は実際の `docker save` を必要とするため、
手順 4 でしか実行できません。

アーカイブされる workspace ファイルと、除外される大きいファイルも表示されます。
必要なものが抜けていないか、この時点で目を通しておくと転送後の手戻りを防げます。

### 4. bundle を作る: `export`（マシン A）

```bash
docker-migration export \
  --container my-ros-container \
  --output ~/migration-bundles
```

`docker save` による image の書き出しと workspace の圧縮を行うため、ここが最も時間の
かかる手順です。数分〜数十分、容量は数十 GB になることを想定してください。完了すると、
自己完結した 1 つのディレクトリができます。

```bash
ls ~/migration-bundles
# migration_bundle_my_workspace_20250101_120000

docker-migration bundle-info \
  ~/migration-bundles/migration_bundle_my_workspace_20250101_120000
```

`EXPORT BLOCKED: …` で停止した場合は、security gate が正しく働いた結果です
（bundle は書き出されていません）。表示された理由を読み、指摘された credential を
実行中のコンテナからではなく **image 側** から取り除き、再ビルドしてからやり直してください。

### 5. bundle をマシン B へコピーする

ディレクトリ構造を保てる方法であれば何でも構いません。回線が切れても再実行できるため、
`rsync` が扱いやすいです。

```bash
rsync -a --info=progress2 \
  ~/migration-bundles/migration_bundle_my_workspace_20250101_120000 \
  target-host:~/migration-bundles/
```

### 6. 届いたものを確認する: `verify`（マシン B）

```bash
cd ~/migration-bundles/migration_bundle_my_workspace_20250101_120000
docker-migration verify .
```

bundle の構成、manifest、記録された security verdict、すべてのチェックサムを再検証します。
転送が途中で切れていたり壊れていたりすれば、作業を進める前にここで分かります。
1 つでも失敗すると終了コードが非ゼロになるので、その場合はコピーをやり直してください。

### 7. 予行演習する: `import --dry-run`（マシン B）

```bash
docker-migration import . --dry-run
```

まだ何も変更しません。移行先の preflight（Docker、空き容量、bundle が必要とする場合は
GPU）を実際に実行したうえで、workspace をどこへ復元するか、どの image を load するか、
`sudo` が必要な手順はどれか、最後に手作業として残るものは何かを提示します。

### 8. 復元する: `import`（マシン B）

```bash
docker-migration import . \
  --workspace ~/ros/my_workspace \
  --ros-domain-id 2
```

image の load、workspace の展開、可搬 Docker 設定の復元、**このマシン用** のホスト固有
ファイルの再生成、コンテナの起動、コンテナ内での依存関係インストールまでを行います。
`sudo` が必要な処理（udev ルールの設置）の前には確認プロンプトが出ます。無人実行したい
場合は `--non-interactive` を付けると、プロンプトはスキップされ、該当作業は手動作業として
報告されます。

`--workspace` は省略できます。省略した場合は、`$DOCKER_MIGRATION_WORKSPACE_ROOT` が
設定されていれば `$DOCKER_MIGRATION_WORKSPACE_ROOT/<workspace name>`、なければ
`~/docker_workspaces/<workspace name>` が使われます。マシン A のパスがマシン B で
再利用されることはありません。

### 9. 動作を確認し、残りを手作業で仕上げる（マシン B）

```bash
docker-migration verify ~/ros/my_workspace --container my-ros-container
less configuration/SECRETS_REQUIRED.md
```

1 つめのコマンドは、Docker アクセス、workspace の構成、設定、起動中のコンテナ、GPU、
ROS、モデル重みを確認します。2 つめは残作業のリストです。各サービスの自分の認証情報、
記録された remote への自分の Git アクセス、アプリケーション固有の secret ファイル、
自分のネットワーク設定などが並びます。credential は bundle で運ばれないため、この手順は
省略できません。

### まとめ（コマンドだけ）

```bash
# マシン A
docker-migration inspect --container my-ros-container
docker-migration export  --container my-ros-container --dry-run
docker-migration export  --container my-ros-container --output ~/migration-bundles
# bundle ディレクトリをマシン B へコピーしてから、マシン B で
docker-migration verify .
docker-migration import . --dry-run
docker-migration import . --workspace ~/ros/my_workspace --ros-domain-id 2
docker-migration verify ~/ros/my_workspace --container my-ros-container
```

## このツールが必要な理由

ロボティクス開発環境を手作業でコピーするのは、遅いだけでなく危険です。

- **`docker commit` の snapshot は credential を持ち出してしまう。**
  長く使い込んだ開発コンテナには、API トークン、SSH 鍵、クラウド認証情報が
  ホームディレクトリのどこかに存在しているのが普通です。いったん image layer に
  入ってしまうと、あとからファイルを削除して再度 commit しても消えません。
  `docker save` は、そのファイルを含む下位 layer をそのまま出力します。
  そこでこのツールは snapshot を export せず、Dockerfile 由来の clean parent image を
  export し、残りは manifest から復元します。
- **「clean parent」はタグ名から推測できない。**
  それらしいタグ名、`env.sh` の変数、`docker history` の出力は、あくまで候補を
  「見つける」ための手がかりであって証明ではありません。このツールは、候補 image の
  `RootFS.Layers` が runtime image の layer chain の完全な prefix であることを
  確認できた場合にのみ export します。
- **動作する環境の半分はホスト固有。**
  UID/GID、デバイスのグループ ID、X11 authority、生成された `.env` や compose override は
  移行先で「再生成」するべきもので、コピーすると起動はするのに後で不可解に壊れます。
- **移行には監査可能な記録が必要。**
  各 bundle には、何を export したか、何を除外したか、どの security gate が走ったか、
  作業者が手動で用意すべきものは何かが記録されます。

## アーキテクチャ

```
src/docker_migration_tool/
├── cli.py                 # argparse CLI: inspect / export / import / verify / bundle-info
├── model.py               # dataclasses: ContainerInfo, ImageInfo, BundleManifest, ...
├── inspect/               # read-only discovery
│   ├── container.py       #   docker inspect -> mounts, env, compose labels, workspace
│   ├── image.py           #   runtime image, snapshot detection, clean-parent proof
│   ├── host.py            #   OS, kernel, CPU/RAM, Docker, GPU, UID/GID, DISPLAY
│   ├── packages.py        #   apt manual list + versions, pip freeze, ROS distro
│   └── workspace.py       #   src tree, git repos, large files, exclusion policy
├── security/              # the gates
│   ├── scanner.py         #   credential *paths* (final filesystem)
│   ├── layers.py          #   credential *paths* in every saved layer
│   └── image_config.py    #   credential key names/values in config + build history
├── export/bundle.py       # bundle assembly, manifest, generated bundle README
├── importers/
│   ├── preflight.py       #   target-machine checks + bundle security verdict gate
│   └── restore.py         #   image load, workspace, config, udev, X11, dependencies
├── verify/checks.py       # bundle integrity and restored-workspace verification
└── utils/                 # docker/compose wrappers, safe archive handling, logging
```

ホスト側の subprocess は引数リスト形式で起動し、`shell=True` は使用していません。
Docker 呼び出しはすべて `utils/docker.py` 経由でタイムアウト付きで実行されます。
なお、コンテナ *内部* では `docker exec sh -c …` のようにシェルを使う箇所があります。
これは意図的な区別で、コマンド文字列を組み立てるのはこのツール自身であり、
使われるシェルはホストではなくコンテナのものです。

## 移行対象

bundle に格納されるもの。

- **clean parent image**（`docker/image/base-image.tar`）。layer prefix による証明と
  secret スキャンを通ったもの。
- **workspace の src ツリー**（`workspace/src.tar.zst`）。権威となる `src` bind mount から
  作成し、モデル重みなどの大きいファイルもチェックサム付きで含めます。
- **`src` 配下の全リポジトリ・サブモジュールの Git 状態**。remote URL、branch、HEAD、
  upstream、ahead/behind、dirty フラグ、変更ファイル一覧、untracked ファイル一覧。
- **パッケージ manifest**。手動インストールした apt パッケージ、apt のバージョン、
  `pip freeze`、ROS distro と Python バージョン、および人が読む用の
  `INSTALLED_DEPENDENCIES.md`。
- **可搬な Docker 設定**。`Dockerfile`、`docker-compose.yml`、`env.sh`、`common.sh`、
  `config.sh`、`.dockerignore`、udev ルール、X11 authority 用スクリプト。
- **ホストとハードウェアの情報**（`host/host_info.json`、`hardware/devices.json`、
  `hardware/network.json`）。移行先と「比較」するための記録であり、値をコピーする
  ためのものではありません。
- **検証チェックリスト**（`verification/checks.json`）と、作業者が自分で用意すべき
  ものを列挙した `configuration/SECRETS_REQUIRED.md`。

## 移行しないもの

- **runtime の snapshot image**。設計上、export しません。
- **credential 全般**。SSH 秘密鍵、API トークン、クラウド認証情報、Docker レジストリの
  ログイン情報、Wi-Fi / NetworkManager の秘密情報、各種 CLI の認証ファイルなど。
- **X11 cookie**。移行先で再生成します。
- **生成済みのホスト固有ファイル**。`.env`、`docker-compose.override.yml`、
  `compose.generated.yml`、`.docker.xauth` など。
- **ビルド生成物**。`build/`、`install/`、`log/`、`__pycache__/`、`core.*` ダンプ、
  `*.jsonl` ログは workspace アーカイブから除外されます。
- **UID/GID、デバイスのグループ ID、`DISPLAY`、デバイスパス**。移行先で検出し、
  `config.sh` が再生成します。
- **カメラのキャリブレーション**。外部パラメータは物理的な設置に依存するため、
  移行先でやり直しになります。

## セキュリティモデル

全体を貫く考え方は 3 つです。

1. **機密そのものは保持しない。**
   path ベースのスキャナは、既知の credential path が「存在するか」（およびサイズ）を
   調べるだけで、ファイル内容は読みません。一方、image config / build history の
   スキャナは性質上異なります。`ENV` / `ARG` の値や history の `CreatedBy` コマンド文字列に
   埋め込まれたトークンを検出するために、実際の値を **メモリ上で** パターンマッチします。
   ただし保持する情報は意図的に絞っており、source、キー名、finding の種別、
   値マッチの場合は `matched: true` だけです。credential の値そのものや history コマンドの
   全文は、ログ、`MANIFEST.json`、bundle 内のファイル、レポートのいずれにも書きません。
   *検出範囲の限界*: 対象は既知の credential path とサポート済みの credential 形式です。
   未知・独自・難読化された secret 形式は見逃す可能性があるため、スキャン通過は
   「強い根拠」であって「不存在の証明」ではありません。
2. **検証できていないものは安全ではない。**
   実行できなかったスキャンは pass ではなく `error` として扱います。image config が
   読めなければ export は中止されます。security metadata を持たない bundle は、
   import 時に unsafe legacy bundle として拒否されます。
3. **名前より証明。**
   export する image は layer chain の比較で決め、workspace アーカイブの取得元は
   実際の bind mount です。名前から組み立てたパスは使いません。

名前が credential らしい環境変数（`*KEY*`、`*TOKEN*`、`*SECRET*`、`*PASSWORD*`、
`*CREDENTIAL*`、`*AUTH*`、`*PRIVATE*`、`AWS_*`、`OPENAI_*`、`ANTHROPIC_*`、`GITHUB_*`、
`AZURE_*`、`DOCKER_*`、`NPM_*`、`PYPI_*`）は、表示・保存のいずれでも `[REDACTED]` に
置き換えられます。

## 必要環境

移行元・移行先の両方で必要なもの。

- **Python 3.10 以降**（PEP 604 の `X | Y` 記法を使用）。サードパーティの実行時依存は
  ありません。
- **Docker Engine** と `docker compose` プラグイン、および daemon にアクセスできる
  ユーザー。両者の存在と daemon の応答は確認しますが、最低バージョンの強制はしません。
- **`zstd`** コマンド。workspace アーカイブの圧縮・展開に使います。
- **`git`**。workspace のリポジトリ状態取得に使います（export 側）。
- **`sudo`**。import 時の udev ルール設置のみで必要です（任意・確認プロンプトあり）。
- **NVIDIA ドライバ + `nvidia-container-toolkit`**。bundle が GPU を必要とする場合のみ。
  preflight で `nvidia-smi` と `nvidia-container-cli` を確認します。
- 移行先の空きディスク容量。preflight は **60 GB** を要求します（bundle と展開後の
  image の合計）。

## インストール

### Ubuntu 22.04

```bash
git clone <your-remote-url> docker-migration-tool
cd docker-migration-tool
pip install -e .
```

### Ubuntu 24.04（PEP 668 対応システム）

Ubuntu 24.04 以降、または PEP 668（externally-managed-environment）を強制する
システムでは、先に仮想環境を作成してください。

```bash
# 前提パッケージのインストール
sudo apt install -y python3-venv python3-pip git zstd

# リポジトリのクローンと移動
git clone <your-remote-url> docker-migration-tool
cd docker-migration-tool

# 仮想環境の作成と有効化
python3 -m venv .venv
source .venv/bin/activate

# インストール
python -m pip install --upgrade pip
python -m pip install -e .
```

これで `error: externally-managed-environment` を回避できます。
`--break-system-packages` は**使用しないでください**。

`docker-migration` コマンドがインストールされます。開発時は
`pip install -e ".[dev]"` を使ってください。

## CLI

```
docker-migration [--version] [--no-color] [-v|--verbose] <command> ...

inspect      --container/-c NAME  [--output/-o FILE]
export       --container/-c NAME  [--output/-o DIR] [--dry-run]
import       BUNDLE_PATH  [--workspace/-w PATH] [--ros-domain-id N]
                          [--dry-run] [--non-interactive]
verify       PATH  [--container/-c NAME]
bundle-info  BUNDLE_PATH
```

`--output` は実際の `export` では必須、`export --dry-run` では任意です
（dry-run は何も書き出しません）。`verify` は指定された `PATH` が bundle か
（`MANIFEST.json` がある）復元済み workspace か（`docker/` または `src/` がある）を
自動で判定します。

## inspect

読み取り専用です。`--output` を指定しない限り、何も書き出しません。

```bash
docker-migration inspect --container my-ros-container
docker-migration inspect --container my-ros-container --output inspection.json
```

出力される内容は、コンテナ情報（mount ごとの分類、環境変数名、compose ラベル）、
runtime image とそれが snapshot かどうか、clean parent の証明結果（却下した候補と
その理由を含む）、ホスト・ハードウェア・ネットワークインターフェース、
workspace の Git リポジトリと dirty 状態、アーカイブに含まれる大きいファイルと
ポリシーで除外された大きいファイル、パッケージ manifest、コンテナ内で検出された
credential path です。

最後に `Clean parent image proven - export is possible` または
`Clean parent image NOT proven - cannot export` が表示されます。

## export dry-run

```bash
docker-migration export --container my-ros-container --dry-run
```

dry-run は、実行できるチェックは実際に実行し、できないものは明示します。

- clean parent の layer prefix 証明 — **実行される**
- image config / build history の credential スキャン — **実行される**
  （`docker image inspect` と `docker image history` だけで済むため）。
  ここで検出されれば dry-run 自体が中止されます。
- final filesystem の credential path スキャン — **実行される**
- image layer 全体の secret スキャン — **スキップ**。dry-run は `docker save` を
  実行しないため。

3 つの状態は個別に表示されます（例: `config_metadata_scan: passed`、
`final_filesystem_scan: passed`、`layer_scan: skipped_dry_run`）。最後に
`Export safety is NOT fully verified in dry-run` が出力されます。
「すべての必須セキュリティチェックに合格」という一括表示が出るのは、実際の export で
3 つのスキャンがすべて通過したときだけです。

アーカイブ対象の情報も表示されます。解決された `src` アーカイブのルート、除外ポリシー、
含まれる大きいファイル、ポリシーにより除外された大きいファイルです。

## export

```bash
docker-migration export \
  --container my-ros-container \
  --output ~/migration-bundles
```

処理順序は、inspection の検証 → manifest の初期化 → parent relationship の証明 →
image config と build history のスキャン → final filesystem のスキャン →
bundle ツリー作成 → image の export とスキャン → workspace のアーカイブ →
Git 状態・パッケージ・Docker 設定・ホスト情報・ハードウェア情報・
`SECRETS_REQUIRED.md`・検証チェックリストの書き出し → `MANIFEST.json` と
bundle 自身の README の生成、です。

いずれかの gate で失敗した時点で export は中止されます。layer スキャンが image を
拒否した場合、生成された `docker save` のアーカイブは bundle に残さず破棄されます。

## bundle-info

```bash
docker-migration bundle-info ~/migration-bundles/migration_bundle_my_workspace_20250101_120000
```

展開せずに、作成時刻、ツールバージョン、移行元ホストの概要、workspace 名と
コンテナ名、export **されなかった** runtime image、clean base image とそのサイズ、
security metadata（parent relationship、layer スキャン、config スキャン、
各 scanner のバージョン）、コンポーネント一覧を表示します。

## verify

```bash
# bundle: structure, manifest, security metadata, checksums, image archive
docker-migration verify ~/migration-bundles/migration_bundle_my_workspace_20250101_120000

# 復元済み workspace: Docker アクセス、構成、設定、コンテナ、GPU、ROS、モデル重み
docker-migration verify ~/docker_workspaces/my_workspace --container my-ros-container
```

チェックに 1 つでも失敗すると、終了コードは非ゼロになります。

## import dry-run

```bash
docker-migration import ~/migration-bundles/migration_bundle_my_workspace_20250101_120000 --dry-run
```

preflight は実際に実行されます（bundle の security verdict ゲートを含む）。そのうえで、
どこへ復元するか、どの image を load するか、workspace を展開し Docker 設定を復元すること、
`sudo` が必要な手順、このホストで再生成されるもの、最後まで手作業で残る項目が
報告されます。変更は一切行われません。

## import

```bash
docker-migration import ~/migration-bundles/migration_bundle_my_workspace_20250101_120000 \
  --workspace ~/ros/my_workspace \
  --ros-domain-id 2
```

処理は、preflight → 対象 workspace の決定 → clean image の `docker load` →
workspace アーカイブの展開 → 可搬 Docker 設定の復元 → udev ルールの設置
（`sudo` を確認、スキップ可）→ X11 authority 同期の設定 → `config.sh` による
`.env` と `docker-compose.override.yml` の再生成 → `ROS_DOMAIN_ID` の調整 →
`docker compose up -d` とコンテナ内での依存関係インストール → 残った手動作業の表示、
という順に進みます。

対象 workspace の決定順序は次の通りです。

1. `--workspace/-w`
2. `$DOCKER_MIGRATION_WORKSPACE_ROOT/<workspace name>`
3. `~/docker_workspaces/<workspace name>`

移行元マシンのパスが移行先のパスとして再利用されることはありません。無人実行では
`--non-interactive` を使います（プロンプトはスキップされ、該当する作業は手動作業として
報告されます）。

### `--workspace` の意味

`--workspace` は workspace を復元する**ファイルシステム上のパス**を指定します。
workspace の論理的な名前（identity）を変更するものではありません。移行元 manifest の
`workspace_name` はそのまま `MANIFEST.json` に保持され、出自の追跡に使われます。
コンテナ名や compose project 名は、復元先パスの basename ではなく、元の
`workspace_name` から導出されます。

同じ workspace を 1 台のマシン上で異なる identity で複数動かす必要がある場合は、
import 後に `env.sh` / `docker-compose.yml` の `CONTAINER_NAME` /
`COMPOSE_PROJECT_NAME` を手動で編集してください。

## 移行フロー

```
on the source machine                on the target machine
─────────────────────                ─────────────────────
1. inspect   (read-only)
2. export --dry-run  (gates 1-3)
3. export            (gates 1-4)
4. bundle-info       (sanity)
   ── copy the bundle directory ──▶  5. bundle-info
                                     6. verify <bundle>
                                     7. import --dry-run
                                     8. import
                                     9. verify <workspace> -c <container>
                                    10. work through SECRETS_REQUIRED.md
```

## Bundle構成

```
migration_bundle_<workspace>_<timestamp>/
├── MANIFEST.json                     # metadata, checksums, security verdict
├── README.md                         # generated, human-readable instructions
├── docker/
│   ├── image/
│   │   ├── base-image.tar            # the clean parent image
│   │   └── IMAGE_INFO.json
│   └── config/
│       ├── Dockerfile
│       ├── docker-compose.yml
│       ├── env.sh
│       ├── common.sh
│       ├── config.sh                 # regenerates .env and the compose override
│       ├── .dockerignore
│       ├── udev/
│       │   └── 99-robotics-docker.rules
│       ├── install_host_udev_rules.sh
│       ├── install_user_xauthority_sync.sh
│       └── xauthority/
├── workspace/
│   ├── src.tar.zst                   # the workspace src tree
│   ├── EXCLUDED.txt                  # exclusion policy, as applied
│   ├── LARGE_FILES.json              # included large files + checksums
│   └── EXCLUDED_LARGE_FILES.json     # large files skipped, with the pattern
├── git/
│   └── repos.json                    # per-repo and per-submodule state
├── packages/
│   ├── apt_manual.txt
│   ├── apt_versions.txt
│   ├── pip_freeze.txt
│   ├── packages_meta.json
│   └── INSTALLED_DEPENDENCIES.md
├── host/
│   └── host_info.json
├── hardware/
│   ├── devices.json
│   └── network.json
└── configuration/
    ├── SECRETS_REQUIRED.md
    ├── detected_secrets.json         # paths and kinds only, never contents
    └── GENERATED_FILES_NOTE.txt
```

## Workspaceの扱い

アーカイブの取得元は、`docker inspect` が報告する **権威ある `src` bind mount** です。
workspace 名から推測したパスは使わず、workspace のルートもアーカイブしません
（可搬 Docker 設定は別の collector が収集するため、ルートをアーカイブすると重複し、
生成ファイルを巻き込む危険があります）。

workspace mount は「形」で判定します。システム領域を除いた bind mount のうち、
パスの末尾が `src` というディレクトリのものです。したがって workspace ディレクトリの
名前は何でも構いません。

除外ポリシーの定義は `inspect/workspace.py` の **一か所だけ** です
（`**/__pycache__`、`**/build`、`**/install`、`**/log`、`core.*`、`*.jsonl`、および
`.env`、`docker-compose.override.yml`、X11 authority ファイルなどの生成ファイル）。
アーカイブ作成、大きいファイルの探索、チェックサム、dry-run レポートはすべて
この一か所を参照するため、除外されたファイルが「含まれる大きいファイル」として
報告されることはありません。

ポリシーを通過した 10 MB 超のファイル（特にモデル重み）はアーカイブに含まれ、
チェックサム付きで `workspace/LARGE_FILES.json` に記録されます。除外されたものは、
除外したパターンとともに別ファイルに記録されます。

## Git状態の扱い

`git/repos.json` には、`src` 配下のすべてのリポジトリとサブモジュールについて、
パス、remote URL（再エンコードせずそのまま）、branch、短縮 HEAD、upstream、
ahead/behind、dirty フラグ、変更ファイル、untracked ファイルが記録されます。
dirty なリポジトリや untracked ファイルがある場合は export 時に警告されるので、
「どのリモートにも存在しない変更」を bundle が運んでいることに気づけます。

Git の認証情報は収集しません。移行先では、記録された remote に対して自分の鍵または
トークンで認証してください。

## Packageの復元

bundle が運ぶのはインストール済みのツリーではなく manifest です。手動インストールした
apt パッケージ、apt の正確なバージョン、`pip freeze`、ROS distro と Python バージョン、
および読みやすい `INSTALLED_DEPENDENCIES.md` が含まれます。

import ではコンテナ起動後に、workspace 自身の
`_container_setup/install_workspace_dependencies.sh` をコンテナ **内部** で実行し
（タイムアウト 30 分）、依存関係のインストールと workspace のビルドを行います。
この絶対パスはハードコードされていません。manifest に記録されたコンテナ側 workspace パスを
まず使い、見つからなければコンテナユーザー自身の `$HOME` 配下を探索します。
インストーラが見つからない場合は、その旨を明示して失敗し、手動作業として報告されます。

## Host / Hardware情報

ホストとハードウェアの情報は **診断用** であり、そのまま復元されることはありません。

- `host/host_info.json`: OS、カーネル、アーキテクチャ、CPU、RAM、Docker と Compose の
  バージョン、GPU モデルとドライバ、UID/GID とグループ一覧、空き容量、`DISPLAY`。
- `hardware/devices.json`: カメラやシリアルデバイスの安定した `/dev/*/by-id`・`by-path` 名、
  USB デバイス一覧、DRI・サウンドデバイス、`dri` / `audio` / `render` のグループ ID。
- `hardware/network.json`: インターフェースごとの *intent*（名前、種別、アドレス、
  サブネット、ゲートウェイ、接続名、用途）。credential は一切含みません。

移行先では、UID/GID、デバイスのグループ ID、`DISPLAY` をローカルで検出し、
`config.sh` が再生成する `.env` に書き込みます。デバイスパスは前提にせず検証し、
キャリブレーションは手動作業です。

## Secretの扱い

- credential path スキャナは、よくある配置（SSH 秘密鍵と config、Docker レジストリの
  設定、クラウド認証情報ディレクトリ、AI CLI の認証ファイルなど）を
  `/home/*/.ssh/id_*` のような **ユーザー名に依存しない glob** として持っています。
  特定のアカウント名は埋め込まれていません。
- これらのチェックは存在とサイズのみを確認するため（`[ -e … ] && stat -c %s`）、
  ファイル内容は読みません。結果は path + 種別（+ サイズ）として
  `configuration/detected_secrets.json` に記録されます。
- image config / build history のスキャナは、メモリ上で実際の値をパターンマッチします。
  `ENV`、`ARG`、`RUN` に焼き込まれたトークンを見るには、それ以外に方法がないためです。
  記録されるのは source、キー名、finding の種別だけで、値そのものや history コマンドの
  全文は記録しません。
- 検出範囲は、既知の credential path とサポート済みの credential 形式に限られます
  （例: `sk-…`、`sk-ant-…`、`ghp_…`、`AKIA…`、`Bearer …`、JWT、PEM 秘密鍵ヘッダ、
  `scheme://user:pass@host`）。独自形式や難読化された secret は検出できない場合があります。
  クリーンな結果は強いチェックではありますが、保証ではありません。
- `configuration/SECRETS_REQUIRED.md` には、移行先の作業者が用意すべきものが
  列挙されます。各サービスの自分の認証情報、記録された remote への自分の Git アクセス、
  アプリケーション固有の secret ファイル、再生成される X11 cookie、自分のネットワーク設定です。
- credential らしい名前の環境変数は、すべての出力で redaction されます。

## セキュリティゲート

bundle が生成されるまでに、次の 4 つの gate すべてを通過する必要があります。

| # | Gate | `docker save` が必要か | 何で止まるか |
|---|------|----------------------|-------------|
| 1 | clean parent の証明 | 不要 | 候補の `RootFS.Layers` が runtime image の chain の完全な prefix（または一致）でない → `EXPORT BLOCKED: Unable to prove clean parent image relationship` |
| 2 | image config + build history の credential スキャン | 不要 | `Config.Env`、`ContainerConfig.Env`、`Cmd`、`Entrypoint`、`Labels`、history の `CreatedBy` に credential らしいキー名または credential 形式の値がある場合。config が読めない場合も同様 |
| 3 | final filesystem の credential path スキャン | 不要 | image の最終ファイルシステムに既知の credential path が存在する場合 |
| 4 | image layer 全体の secret スキャン | 必要 | save されたアーカイブの **いずれかの** layer に credential らしい path がある場合。あとから whiteout で削除していても、下位 layer は出力に含まれるため無効 |

gate 2 が重要なのは、gate 3 と gate 4 が *path* で判定するからです。
`ENV OPENAI_API_KEY=...`、`ARG GITHUB_TOKEN=...`、
`RUN curl -H "Authorization: Bearer ..."` のように焼き込まれた secret には、
そもそも path がありません。キー名は名前の *構成要素* 単位で照合するため、
`--keyring=`、`KEYSTORE`、`XAUTHORITY` はクリーンな export を妨げません。値の判定は
部分一致ではなく形式を限定した正規表現（`sk-…`、`sk-ant-…`、`ghp_…`、`AKIA…`、
`Bearer …`、JWT、PEM 秘密鍵ヘッダ、`scheme://user:pass@host`、入れ子の
`TOKEN=` / `API_KEY=` 代入）で行うため、通常のパッケージ名やバージョン指定は
finding になりません。finding が保持するのは
`source` / `key` / `kind` / `matched: true` で、値は含みません。

import 側の gate は対称です。preflight は、`parent_relationship_verified` が true で、
かつ `layer_secret_scan_result` と `image_config_scan_result` の両方が `passed` でなければ
bundle を拒否します。security metadata を持たない bundle は、信頼せず
unsafe legacy bundle として拒否します。

なお、これらの gate はいずれも既知の path と形式に対する best-effort です。
未知の secret 形式を 100% 検出できる保証はないので、渡す内容そのものの確認は
引き続き必要です。

## 使用例

```bash
# ── source machine ────────────────────────────────────────────────────────────
docker-migration inspect --container my-ros-container --output inspection.json
docker-migration export  --container my-ros-container --dry-run
docker-migration export  --container my-ros-container --output ~/migration-bundles
docker-migration bundle-info ~/migration-bundles/migration_bundle_my_workspace_20250101_120000

# ── copy the bundle (any method that preserves the directory) ────────────────
rsync -a --info=progress2 \
  ~/migration-bundles/migration_bundle_my_workspace_20250101_120000 \
  target-host:~/migration-bundles/

# ── target machine ───────────────────────────────────────────────────────────
cd ~/migration-bundles/migration_bundle_my_workspace_20250101_120000
docker-migration verify .
docker-migration import . --dry-run
docker-migration import . --workspace ~/ros/my_workspace --ros-domain-id 2
docker-migration verify ~/ros/my_workspace --container my-ros-container
less configuration/SECRETS_REQUIRED.md
```

## 制限事項

- **Linux ホスト専用**で、移行元と移行先のアーキテクチャは同じである必要があります。
  image は再ビルドせず、そのまま転送します。
- **bundle は大きい**。clean な ROS image とモデル重みを含む workspace で、数十 GB に
  なることが普通です。preflight は 60 GB の空きを要求します。
- **差分転送や再開機能はありません。** bundle のコピー自体は利用者の責任です。
- **workspace は `<workspace>/src` 構成**で、コンテナへ bind mount されている必要が
  あります。依存関係インストールの手順を使う場合、インストーラは
  `src/_container_setup/install_workspace_dependencies.sh` に置いてください。
- **dirty な Git 状態は記録して運ぶだけで、解決はしません。** 未コミットの作業は
  アーカイブに入りますが、マージ処理は行いません。
- **ロボットのネットワーク設定、udev を超えるデバイス権限、カメラキャリブレーションは
  手動**です（設計上の割り切り）。
- **credential は意図的に持ち出さず、gate は best-effort です。** 移行先では各サービスの
  再認証が必要になります。スキャナが見ているのは既知の credential path と
  サポート済み形式なので、未知・難読化された形式はすり抜ける可能性があります。
  結果が緑であることだけに頼らず、渡す内容を確認してください。
- **dry-run は安全性の証明書ではありません。** gate 4 は `docker save` なしには
  実行できません。

## 開発

```bash
pip install -e ".[dev]"
```

構成の約束: 製品コードは `src/docker_migration_tool/`、テストは `tests/` に置きます。
ホスト側の subprocess は引数リストで起動し、`shell=True` は使いません
（コンテナ側では、このツールが組み立てた `sh -c` / `bash -c` の文字列を使う箇所が
あります）。Docker 呼び出しはすべてタイムアウト付きで `utils/docker.py` を通り、
アーカイブ展開は `utils/filesystem.py` を通ります。後者は path traversal、絶対パス、
symlink による脱出、デバイスノードを拒否します。

コードを変更する前に知っておくべきルールが 2 つあります。

1. workspace の除外ポリシーの定義は 1 か所だけ（`inspect/workspace.py`）。
   利用側は必ずそこから読むこと。
2. security スキャナは「存在情報のみを記録する」方針を守ること。検出器を追加する場合は、
   それが export を止めることを示すテストを一緒に追加し、マッチした値をログや記録に
   残さないこと。

## テスト

```bash
python -m pytest                       # 308 tests
python -m pytest --collect-only -q     # collection only
python -m pytest tests/test_security.py
```

テストはすべて Docker 呼び出しをモックした単体テストです。daemon、コンテナ、ネットワークは
不要で、実行時間は 1 秒未満です。対象には、layer prefix の証明、4 つの security gate、
config / history の credential スキャナ（89 テスト）、workspace の除外ポリシー、
アーカイブ安全性、manifest の security metadata、ログの redaction、そして
マシン固有のパスや識別子が製品コードへ再混入した場合に失敗する publication-safety
モジュールが含まれます。

## 安全性に関する設計

以下はコードが実際に強制している内容です。あらゆる secret を必ず検出できるという
主張ではありません。gate が見ているのは既知の credential path とサポート済みの
credential 形式です。

- snapshot image は export しません。
- image を export するのは、その layer chain が runtime image の chain の prefix であると
  証明できた場合だけです。
- いずれかの layer に credential らしい path がある場合、image config / build history に
  credential らしいキーや値がある場合、final filesystem に credential path がある場合、
  export は中止されます。
- 拒否された `docker save` のアーカイブは破棄され、bundle には残りません。
- path ベースのスキャナはファイル内容を読まず、path・種別・サイズを記録します。
  config / history スキャナはメモリ上で値を照合しますが、保存するのは source、キー名、
  種別、`matched: true` だけです。credential の値や history コマンドの全文は、ログ、
  manifest、bundle 内のファイル、レポートのいずれにも残りません。
- security verdict が欠けている、または通過していない bundle は import 時に拒否されます。
- `inspect` と `--dry-run` は Docker の状態を変更せず、workspace にも書き込みません。
- 移行元のパス、UID、GID、デバイス ID、ホスト名を移行先の値として再利用しません。
  移行先の値は import 時に検出します。

## ライセンス

MIT — [LICENSE](LICENSE) を参照してください。
