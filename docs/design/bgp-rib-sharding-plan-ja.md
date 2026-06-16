# BGP RIB シャーディング（Juniper 方式）

ステータス: **Phase 0 + A はマージ済み。Phase B は N=1（同期ディスパッチ）で
構築済み。ポリシー並列化の C.1/C.2 構築済み。N シャードの専用スレッドプール +
RouteBatch + mimalloc 構築済み。シャードごとの inbound ポリシー複製
（`PolicyReplace`）構築済み。Phase E.1（advertise 結果の並列事前計算）+ E.2
（上限付き egress ワーカープール）構築済み。Adj-RIB-Out は全ファミリで統一済み
（BatchAfi/LabeledAfi）** — Phase 0 + A は 2026-06-12 にマージ
（PR #1402/#1406/#1408/#1416）。Phase A 以降はすべてブランチ
`bgp-nshard-policy-shard` 上に **未マージ** で存在する（2026-06-14 時点で
`main` より 55 コミット先行、PR はまだなし）。§5–8 の計画から意図的に逸脱した
3 点: **B.3 はタスクの spawn ではなく同期ディスパッチになった**、
**再スコープした Phase C は純粋なポリシーウォークを並列化（rayon）する**、
**マルチシャードのファンアウトは tokio タスクではなく専用 OS スレッド上で動く**。
シャード数は現在 **実行時の環境変数で駆動** される — `ZEBRA_BGP_SHARDS`
（1–64 にクランプ、デフォルト 1）で、egress プールのサイズは
`ZEBRA_BGP_UPDATE_WORKERS`（デフォルト `max(1, cores − shards)`）で決まる。
コンパイル時の `SHARDS` 定数は廃止された。出荷形態としては YANG ノブが依然
として将来案。
以下の「実装ステータス」セクションが現時点での正式なアーキテクチャである。
§1–10 は元々の適用可能性分析と設計根拠のまま残してある。Open decision §8:
D1（リポジトリ内 `bgp-bench`）と D3（v4/v6-unicast+LU+VPN のスコープ）は推奨
どおりに解決。D2（チャネルの上限）は当面 **上限なし** で解決（シャードの inbox
と結果チャネルの両方）— バックプレッシャは追跡中の改善項目、§12 参照。
D4（デフォルトのシャード数）— デフォルトは 1（環境変数によるオプトイン）、
性能の knee は N=4 で計測。

出典: 「BGP RIB Sharding」— Ravindran Thangarajah, Juniper Networks,
2022-10-24。
<https://community.juniper.net/blogs/ravindran-thangarajah/2022/10/24/bgp-rib-sharding>

## 実装ステータス（構築済みの状態 — 2026-06-14）

実際に出荷された内容は §5–8 の計画から、意図的に 3 つの点で逸脱している:
B.3 はタスクの spawn ではなく **同期ディスパッチ** になった。Phase C は純粋な
ポリシーウォークを並列化する形に **再スコープ** された（rayon）。そして
マルチシャードのファンアウト（元の C.1）は、スライスをエンドツーエンドで所有
する **専用 OS スレッド** 上で動き、tokio のシャードタスクではない。
シャーディングに加えて egress パスも **統一** された — 全ファミリ
（v4/v6 unicast、VPNv4/6、labeled-unicast v4/v6）が、2 つのジェネリック
トレイトの背後に機能する Adj-RIB-Out を持つようになった。これは Phase E.2+
（グループ親和性の update-worker）が構築される土台である。§5–10 は元々の設計
根拠のまま。§11 は BIRD/GoBGP の先行事例との比較、§12 は現在の改善ロードマップ。

### Phase B — N=1 でのシャード抽出（B.1–B.3、構築済み）

- **状態分割（B.1）。** `BgpShard`（`bgp/shard/mod.rs`）がシャード化された
  Loc-RIB テーブル — `v4`、`v6`、`v4lu`、`v6lu`（`LocalRibTable<…>`）と
  `v4vpn`、`v6vpn`（`BTreeMap<RouteDistinguisher, LocalRibTable<…>>`）— に
  加えて、ピアごとの Adj-RIB-In スライス（`adj_in: BTreeMap<usize,
  ShardAdjIn>`）、シャードが所有する属性 interning ストア、`ShardLabelPool`
  （ルートごとの LU / VPNv4-transit ラベルのサブブロック）を所有する。
  EVPN / flowspec / SR-Policy / BGP-LS / RTC は main 所有のまま（§8 D3）。
- **Attr ストアは ahash を使う**（`store.rs`）。プロファイルではデフォルトの
  SipHash がデーモン CPU の約 28% を占めていた。interned キーは内部の重複排除
  キーであり攻撃者が選べるものではないため、高速な非暗号学的ハッシャが正しい
  トレードオフ — これにより変換後のパスはベースラインより正味で高速になった。
- **B.3 — 同期ディスパッチ（方針転換点）。** 計画では spawn したシャードタスク
  （`BgpShardHandle`、チャネル）を想定していた。N=1 ではタスクはホップ +
  チャネルのオーバーヘッドを追加するだけで並列性は **ゼロ**（いずれにせよ main
  のコア上で動く）。そこで B.3 は代わりに、テーブル操作を
  `BgpShard::handle(ShardMsg, central) -> Vec<ShardOut>` 経由でルーティング
  し、`route.rs` から **インライン** で呼び出す。`shard` はタスクではなく
  `Bgp` のただのフィールドである。これにより B.1/B.2 の価値 — クリーンな状態
  分割 + 型付きメッセージプロトコルで N>1 へのタスク化が容易 — を、N=1 で
  タスクのコストを払わずに保てる。
  - `ShardMsg`: `UpdateV4` / `UpdateV6` / `UpdateLu`（+ `WithdrawV4/V6/Lu`、
    `PeerDown`、`Show`、`Shutdown`）。`ShardOut`: `BestPathV4/V6/Lu`。
  - update ごとのパイプライン分割: **main** が attr ごとのピアチェック
    （`inbound_attr_checks`）、inbound ポリシー、NHT 解決、Inter-AS
    Option-AB の transit フラグを実行し、**shard** が Adj-RIB-In + intern +
    Loc-RIB insert + best-path + ラベル割り当てを行う。その後 **main** が
    返された best-path のデルタに対して動作する — NHT untrack、FIB install、
    VPN import/export、advertise。
  - **ディスパッチ vs 直接アクセス（N>1 で何が並列化されるか）**:
    **プレーンな v4-unicast のみがプール全体にファンアウトする** —
    `ShardMsg::RouteBatchV4`（シャードごとに 1 バッチ、ハッシュ化。
    このメッセージは unicast 専用で `rd` フィールドを持たない）経由。
    **VPNv4 は意図的に同期 `bgp.shard` に留まる** — その transit ラベルは
    main の中央アロケータを必要とし、スレッド境界を越えて借用できないため、
    `route_ipv4_update_decided` はプールパスを `rd.is_none()` でゲートする
    （`route.rs:2463`）。v6-unicast + VPNv6 は `UpdateV6` 経由でシャードに
    到達するが、これも **単一の同期 `bgp.shard`** 上である（`RouteBatchV6`
    はまだプールにディスパッチされていない）。**labeled-unicast（v4/v6）は
    直接シャードテーブルアクセス** を使う（`bgp.shard.update_v4lu` /
    `update_v6lu`）。したがって N>1 で並列化される best-path はプレーンな
    v4-unicast のみ。VPNv4、v6、VPNv6、LU はすべて main スレッドの同期
    シャードに留まる。`UpdateLu` + `WithdrawLu` + `Show` + `BestPathLu`
    バリアントは、後の移行のために配線済みだが未使用のスキャフォールディング
    である（これらに対する dead-code 警告は想定どおり）。
  - **稼働中の `ShardMsg` 一式**（`shard/msg.rs`）: `UpdateV4`、
    `RouteBatchV4`、`WithdrawV4`、`UpdateV6`（同期のみ）、`PeerDown`
    （ブロードキャスト）、`SoftInV4`（ブロードキャスト）、`PolicyReplace`
    （ブロードキャスト）、`NexthopReachableBatchV4`（バッチ化された NHT
    再評価）。稼働中の `ShardOut`: `BestPathV4`、`BestPathV6`。

### Phase C — 並列ポリシー評価への再スコープ（C.1/C.2、構築済み）

これは *再スコープ後* の C.1/C.2 で、**最初に** 着地した — N=1 で純粋な
ポリシーウォークを並列化するもの。（元計画の C.1、すなわち N シャードの
ファンアウトは後に専用スレッドプールとして着地した — 後述の「Phase N-shard」
と §6 のラベル注記を参照。）この再スコープは、現実的なポリシー負荷の高い
ワークロード（1000 エントリのルートマップを inbound *と* outbound の両方に
適用）で N=1 ビルドをプロファイルした結果から来た。それは **CPU の 74.8% が
`PrefixTrie::walk_enclosing`** に費やされていることを示した — prefix-set の
マッチで、ルートごとに約 1000 回実行される。ポリシー評価は **純粋** であり
（ピアのポリシースナップショット + ルートを読むだけで何も変更しない）、1 つの
UPDATE 内のすべての prefix は 1 つの属性を共有するため、RIB を分割すること
*なく* rayon で並列化できる:

- **C.1 — 並列 inbound ポリシー。** `route_ipv4_update_batch` は
  `inbound_attr_checks` を 1 回実行し、prefix ごとのポリシーウォーク
  （`apply_policy_in_pure`）を `par_iter` し、その後 Loc-RIB への書き込みと
  advertise を NLRI 順に直列で行う。
- **C.2 — 並列 outbound ポリシー。** `route_ipv4_update_decided` は
  インラインで advertise する代わりに advertise ジョブを返す。バッチは続いて
  3 つのフェーズを実行する — 直列の Loc-RIB 更新 → **グループごとの並列
  advertise 結果の事前計算**（`compute_advertise_outcome` は純粋）→ 直列の
  適用（cache / adj-out / NLRI 順での送信）。グループごとの結果は、直列の
  メモが使うのと同じ正規化された（非ソース、非 LLGR）ピアで計算されるため、
  結果は同一であり、グループカウンタの増分はグループごとに 1 回のまま保たれる。

**前提作業 — ファミリ汎用のピアごとポリシー。** ポリシーエンジンは既に
ファミリ汎用だった（`policy_list_apply_net` は `IpNet` を取り、
`PrefixSet::matches` はデュアルスタック）。in/out の適用は 1 つのコア
`apply_policy_net(prefix_cfg, policy_cfg, router_id, IpNet, attr, weight)` に
集約され、両方向と全ファミリで共有される。ピアごとのルートマップは今や
**v4/v6 unicast、VPNv4/6、labeled-unicast v4/v6** に適用される。以前は
v4-unicast + VPNv4 のみが持っていた（v6 / LU は neighbor ポリシーを黙って
無視していた）。`@bgp_v6_route_map` と `@bgp_lu_route_map` で検証済み。

### 計測（12 コア、1000 エントリの in+out ポリシー、4×100k、A/B インターリーブ）

| ビルド | 収束 | 直列比 |
|---|---|---|
| 直列（C.1/C.2 なし） | 19.57 s | — |
| C.1（並列 inbound） | 11.62 s | −41% |
| C.2（並列 inbound + outbound） | **4.34 s** | **−78%（4.5×）** |

勝因はポリシーウォークである。§9 のベースライン行列（ポリシーなし）は別の
ワークロードであり、この並列化はそこではほとんど効果が出ない — そこでは
計画されたマルチシャード / update-worker のファンアウトが効く。

### Phase N-shard — 専用スレッドプール（構築済み、env ゲート、デフォルト off）

計画されたマルチシャードのファンアウト（元の C.1）は構築されたが、
**tokio タスクや rayon ではなく専用 OS スレッド上** に乗っている — UPDATE
ごとの rayon 形態（上記の再スコープ後 C.1/C.2）はポリシーなしのワークロードを
約 36% 退行させた（償却すべきポリシーがない `par_iter` 税）ため、シャードは
スライスをエンドツーエンドで所有する本物のスレッドになった。

- **`ShardPool`**（`bgp/shard/pool.rs`）は `shard_count()` 個のワーカー
  スレッド（`std::thread`、`bgp-shard-{idx}` という名前）を spawn し、
  `BgpShard` ごとに 1 つ割り当てる。ワーカーは `std::sync::mpsc` の inbox で
  ブロックし、`BgpShard::handle` を実行し、`ShardResult` を tokio の
  `UnboundedSender` 経由で送り返す。CPU バウンドの作業を本物のスレッドに
  置くことで、tokio ランタイムと I/O（reader/writer）タスクから引き離せる。
- **`shard_count()`**（`inst.rs`）は `ZEBRA_BGP_SHARDS` を読み、`1..=64` に
  クランプし、デフォルト 1 — 実行時の環境変数駆動でコンパイル時定数はない。
  （出荷形態は YANG ノブ、§12。）
- **`shard_of(addr)`** = アドレスのオクテットに対する FNV-1a `% N`
  （決定論的、アドレスのみ）で、1 つの prefix の unicast / LU / VPN の行が
  クロスシャード同期なしで同居する（Juniper の不変条件）。
- **`shard_count() > 1` でゲート**（`inst.rs`）: デフォルトの `1` では何も
  spawn されず（`(n_shards > 1).then(…)`）、同期 `shard` フィールド +
  バイト同一の同期パスが動き、イベントループの `shard_results_rx` アームは
  アイドルのまま — したがって BDD とすべてのデフォルト実行は実証済みの N=1
  パスを通る。
- **RouteBatch**（`ShardMsg::RouteBatchV4`）: 1 つの UPDATE の prefix 群は
  ハッシュで分割され、**シャードごとに 1 バッチ** として送られる（prefix
  ごとに 1 メッセージではない）。これにより prefix ごとの約 400 万回の futex
  wakeup が約 N 回に折りたたまれる。
- **Phase C — シャード内ポリシー**（`compute_policy: true`）: シャードが
  inbound ポリシーを自分で実行し、main の `par_iter` を取り除く。
- **mimalloc** をグローバルアロケータに（`main.rs`）: スレッドごとのヒープが、
  N=12 のプロファイルでアロケータの `osq_lock` が占めていた CPU の約 12% を
  取り除く（シャードが属性を intern / RIB の行を並行に構築する）。
- **Reduce**（`inst.rs::process_shard_result`）: main のイベントループが
  best-path のデルタを `select!` し、それぞれに対して NHT untrack +
  FIB install + advertise を実行する。

**計測（12 コア、ポリシーなし 8×500k、A/B インターリーブ、NHT release は
バッチ化）。** 切り分けの結果、シャードの *ディスパッチ* は無料（同期ディスパッチ
≈ ベースライン）であり、ahash interning はむしろ役立つこと（−11%）が分かった。
素朴なシャーディングはその後ワークロードを退行させた（ゲートなしの rayon
par_iter で +46%、prefix ごとのディスパッチの嵐、アロケータ競合）。これは
RouteBatch + mimalloc + あらゆる rayon par_iter の一様なコストゲート
（C.1 inbound、C.2 outbound、E.1 reduce）+ シャードごとの NHT-release バッチ化
ですべて修正された。最終状態、`ZEBRA_BGP_SHARDS` をスイープ（1 バイナリ、
再コンパイルなし）:

| ビルド | r1 | r2 | r3 | avg | base 比 |
|---|---|---|---|---|---|
| base（シャーディング前） | 20.89 | 20.79 | 20.51 | 20.73 s | — |
| N=1 | 15.62 | 16.53 | 16.66 | 16.27 s | −22% |
| N=4 | 14.94 | 14.12 | 14.25 | 14.44 s | **−30%（knee）** |
| N=12 | 16.62 | 16.66 | 16.55 | 16.61 s | −20% |

**N=4 がスイートスポット。N=12 はシャード過剰** — 教科書どおりの最適スレッド
曲線（Juniper の「スレッド数 ≤ コア数」、knee を超えると利得は蒸発）。
SHARDS ≈ コア数では main の reduce + tokio I/O に回す予備コアがないため、
ルートごとの作業が些末なワークロードでは、限界的な best-path の利得よりも
協調コストが上回る。ここでの勝因の大半は ahash + mimalloc + par_iter の脱税で
あり、シャードのファンアウトは N=1 から N=4 の knee まで −22%→−30% を加え、
その後退行する。（以前の N=12 での −23% は N>1 の NHT-release 修正の *前* で、
first-sight で保持されたルートが黙って詰まっていた時のもの — これらの数値は
エンドツーエンドで正しく、release のバッチ化で N=12 の run-to-run のばらつきは
約 1.4 s から約 0.1 s に縮んだ。）これはポリシー下（上記の C.1/C.2、N=12 で
E.1 −39%）や高い RIB-FIB ファンアウト（§9）でははるかに効く。

### Phase E — 並列 advertise（reduce が次の直列点）

N>1 ではシャードが best-path を並列化するが、**reduce**
（`process_shard_result`）は依然として advertise — out-policy + 属性変換 +
バケット化 — を main スレッド上で直列に実行していた（*空の* メモを渡すため、
`compute_advertise_outcome` がインラインで動く）。これはまさに、ingest が
シャードに移ったときに *失われた* C.2 の並列性である。エンコード自体は既に
スレッド外（Phase A `FlushJob` → `spawn_blocking`）。Phase E は egress の
残りを直列の reduce から外に出す。

- **E.1（構築済み）— reduce 内での並列 advertise 結果事前計算、コストゲート
  付き。** `route_apply_bestpath_v4_batch` は `ShardResult` 全体に対して
  NHT untrack + FIB install を直列で実行し、その後 — **advertise 対象の
  あるピアに out-policy がバインドされている場合に限り** — (prefix, group)
  ごとの out-policy + 属性変換（`precompute_ipv4_advertise_outcomes`、
  C.2 のルーチン）を `par_iter` し、その後バケット化をメモから直列で適用する。
  N=12 で計測（pre-E.1 の N=12 ビルドと A/B インターリーブ比較）:
  ポリシー負荷の高い 8×100k の収束が **18.97 s → 11.65 s（約 39%）**。
  コストゲートは必須である: SHARDS ≈ コア数では予備コアがないため、
  *ゲートなしの* par_iter は CPU バウンドのシャードスレッドからコアを奪う —
  ゲート前はポリシーなしの 8×500k 負荷が **3.2×** 退行した（15.7 s →
  50.8 s）。egress がボトルネックになる（=シャードがほぼアイドル）のは
  out-policy がある場合だけなので、その場合のみ egress を並列化する。
  そうでなければ直列のインライン適用（バイト同一）が全コアを best-path に
  保つ。*両方とも忙しい* ケース（out-policy + 飽和したシャード、例えば
  `PolicyReplace` 後）の一般的な修正は rayon のコア全体のグローバルプール
  ではなく E.2 の上限付きワーカープールである。
- **E.2（構築済み）— 上限付き egress ワーカープール。** E.1 の out-policy
  事前計算は今や、rayon のコア全体の *グローバル* プールではなく **上限付き**
  rayon `ThreadPool`（`egress_pool().install(…)`）上で動くため、N ≈ コア数
  でも専用シャードスレッドをオーバーサブスクライブできない。サイズは
  `ZEBRA_BGP_UPDATE_WORKERS`、デフォルト `max(1, cores −
  ZEBRA_BGP_SHARDS)` から決まる — これにより **シャード数がコア分割のノブ**
  になる（Juniper のシャード vs update スレッド）: inbound の並列性は
  シャードから、outbound は egress プールから来て、両者がコア数を奪い合う
  のではなく *収まる*。計測（1000 エントリ in+out ポリシー、8×100k）:
  直列ベースライン 42.7 s。**N=4（4 シャード + 8 egress）8.9 s（−79%）** で、
  オーバーサブスクライブした旧グローバルプール N=12（11.9 s）を約 25% 上回る。
  N=12 は egress を飢えさせ（=ワーカー 1 → 直列の out-policy ウォーク）
  20.9 s — 「予備コアなし」の現実が明示され、最適が N=cores ではなく N=4 で
  ある理由を示す。
- **E.2+（将来）— グループ親和性 update-worker。** 完全な Juniper 形態:
  グループごとのキャッシュ + adj-out + エンコードを、静的な group→worker
  親和性を持つ M 個の専用ワーカースレッドに移し、シャードから直接
  `AdvDelta`（RTO）を供給する（main の reduce をバイパス）。BIRD 3.x
  （プロトコルごとのループがロックフリーのジャーナルを pull し、自身の
  スレッド上でフィルタ + エンコードする）と GoBGP（ピアごとの送信
  goroutine）が 2 つの参照設計（§11）。(peer, prefix) ごとの順序は保たれる:
  1 つの prefix → 1 つのシャード → 1 つのワーカー。

### Adj-RIB-Out の統一 — egress の土台（構築済み）

シャード分割とは独立だが同じブランチ上で構築され、egress パスは全ファミリで
統一された。これがここで重要なのは 2 つの理由による: シャードの reduce が
ファミリに関係なく **1 つの** advertise パスを駆動するようになったこと、
そして E.2+（`AdvDelta` を供給されるグループ親和性ワーカー）が diff の対象と
して per-family の Adj-RIB-Out を必要とすること — それは以前は v4/VPNv4 しか
持っていなかった。

- **Phase 1 — v6 / LU / VPNv6 の機能的 Adj-RIB-Out。** これ以前、
  v4-unicast と VPNv4 は本物のピアごとの Adj-RIB-Out（`Peer.adj_out`、
  `adj_rib.rs` の `AdjRib<Out>`）を保持し、それに対して withdraw を
  プルーニングしていた。v6、labeled-unicast（v4/v6）、VPNv6 は **すべての
  withdraw をすべての Established ピアにフラッド** しており、ピアごとの
  egress 状態を持たなかったため、withdraw の ping-pong（ピアに送られた
  ことのないルートにも withdraw が出て跳ね返る）を引き起こしていた。暫定の
  ping-pong ガード（`64f205b6` v6、`d7f048fe` LU、`c12d675f` VPNv6）は、
  各ファミリが本物の `adj_out` スライス（`adj_out.{v6,v4lu,v6lu,v6vpn}`）を
  得た時点で削除された — テーブルにないピアには偽の withdraw が送られない
  だけなので、このバグクラスは **構造的に** なくなった。
- **Phase 2 — 2 つのトレイトによるジェネリック advertise。** ファミリごとの
  `route_advertise_to_peers_{v4,v6,vpnv4,vpnv6}` 関数は 1 つの
  `route_advertise_batch::<A: BatchAfi>`（impl は `V4Batch` / `V6Batch`、
  v4/v6 unicast + VPNv4/6 をカバー）に集約され、labeled-unicast のペアは
  1 つの `route_advertise_labeled::<A: LabeledAfi>`（impl は `LabeledV4` /
  `LabeledV6`）に集約された。`BatchAfi` トレイトは `compute_outcome`
  （E.1/E.2 の reduce が並列化する純粋な out-policy + 属性変換）、
  `advertise`、`withdraw`、`advertise_addpath` を持つ。`LabeledAfi` は
  ピアごとの `adj_out_*` diff プリミティブに加え `update`/`apply_policy_out`
  を持つ。
- **AddPath — 全候補を advertise**（`3a27ec65`）: イベント駆動の v6 と LU
  AddPath パスは、best のみの `selected`（≤1 パス）ではなく、シャードから
  **Loc-RIB の全候補集合** を読むようになった（`bgp.shard.v6.0.get(prefix)`
  / `A::all_cands`）。以前はイベントパスで best 以外の AddPath 候補を黙って
  落としていた。v4/VPN は既に候補ごとに advertise していた。

update-group キャッシュ（`cache_ipv4` …）と `UpdateGroupSig` は変更なし —
シグネチャはセッションごとであってファミリごとではないため、統一に新しい
バリアントは不要だった。

### まだ将来（直近のシャーディングのギャップ）

- **VPNv4 / v6 / VPNv6 / LU のプールディスパッチ。** N>1 ではプレーンな
  v4-unicast のみがファンアウトする。VPNv4、v6、VPNv6、LU の best-path は
  依然として単一の同期シャード上で動く。VPNv4 はラベル割り当てをシャード側に
  保つプールパスが必要（今日の transit ラベルは main の中央アロケータを
  借用する）。v6/VPNv6 は `RouteBatchV6` が必要。LU は
  `UpdateLu`/`WithdrawLu` のスキャフォールディングの有効化が必要。
- **N>1 のバリア**（計画 C.3）: EoR / route-refresh / GR-LLGR のスイープは
  シャード間で broadcast-and-ack にならなければならない。
- **N>1 の v4-unicast read パス**（B.4）— **クリティカル**: `show bgp
  ipv4`、セッション確立時の `route_sync_ipv4`、`clear`/soft-in はすべて
  同期 `bgp.shard.v4` を読むが、N>1 ではそこは空である（v4-unicast が唯一の
  プール化ファミリで、reduce は best-path を書き戻さない）。オペレータは v4
  RIB を見られず、ルート存在後に確立したピアは何も受け取らない。
  フォワーディングには影響しない。（以前の「`Show` は配線済み」という注記は
  誤りだった — `@bgp_shard_v4_sync` で反証。）修正計画と推奨設計を以下に。
- **YANG ノブ** `router bgp shards <1-64>` で `ZEBRA_BGP_SHARDS` を出荷形態
  として置き換える（計画 C.4）、加えて性能行列 + デフォルト。
- **`PolicyReplace` 正当性スイープ。** inbound ポリシーのスナップショットは
  今やシャードに複製される（`BgpShard.in_policy`、ブロードキャスト
  `PolicyReplace`）。残作業はライブ再設定の再評価パス（単に保存するのでは
  なく、新しいスナップショットに対して best-path を再実行する）。

より大きなアーキテクチャ上の改善 — BIRD/GoBGP の調査（§11）から得たもの —
は §12 にまとめてある。

### N>1 での read パスの scatter-gather — バグ + 修正計画（B.4）

**ステータス（着地済み、ブランチ `bgp-shard-sync-mirror`）:** 正当性バグは
**read レプリカミラー** で修正された。これは実証済みの同期アーキテクチャを
main タスク上で同期のまま保つ（async リファクタなし）ために選んだ。プールの
reduce（`route_apply_bestpath_v4_batch` → `BgpShard::mirror_v4`）が各 v4
best-path のデルタを main シャードの `bgp.shard.v4` に書き込む — 候補テーブル
（`v4.0`、`show bgp ipv4` が読む）と best-path テーブル（`v4.1`、非 AddPath の
`route_sync_ipv4` が読む）の両方 — ので、*変更されていない* 同期 read パスが
N>1 でもルートを見られる。`@bgp_shard_v4_sync` はグリーンで、
`@bgp_shard_policy` は影響を受けない。トレードオフ: FIB サイズの v4 レプリカが
main に住むようになり（シャーディングのメモリ利得の一部を返上）、同期の
*ビルド* は依然として main タスク上で直列に動く。以下の scatter-gather /
シャード内並列のオプションは、この直列ビルドがいずれボトルネックになった場合に
並列同期 **egress** へ至るパスとして残る — それらは今や正当性の修正ではなく
性能のフォローアップである。

**バグ（クリティカル、v4-unicast のみ）。** N>1 では、プレーンな v4-unicast
の best-path はプールシャード内にしか存在しない。reduce
（`reduce_bestpath_v4_nht_fib`）はデルタから FIB-install + advertise を行うが、
同期 `bgp.shard.v4` を一切埋めない。そのため、それを参照するすべての read
パスは空を返す: `show bgp ipv4`、セッション確立時のダンプ `route_sync_ipv4`、
`clear`/soft-in。オペレータは v4 RIB を見られず、ルート存在後に確立したピアは
EoR マーカーしか受け取らない。フォワーディングには影響しない（イベント駆動の
advertise はデルタから動く）。`@bgp_shard_v4_sync` BDD でロックされている
（修正まで赤）: 早期ピアはイベント駆動パスでルートを学習し（コントロール、
グリーン）、遅延ピアは同期で何も得ず（バグ、赤）、シャード化ノード自身の
`show bgp ipv4` は空（バグ、赤）。

**並列化すべき作業。** フルダンプ/show は RIB の *読み取り* で律速されない —
ルートごとの egress ビルドである: `route_update_ipv4`（next-hop-self、
AS_PATH）、out-policy の `PrefixTrie::walk_enclosing`（プロファイルの
CPU 74.8% のホットスポット）、intern、エンコード。ルートリフレクタにとっては
新規ピアごとに数百万ルートになる。*そのビルドがどこで動くか* が、修正が
マルチコアマシンでスケールするかを決める。

**オプション。**

- **A1 — gather-then-build。** シャードが生の `(prefix, BgpRib)` 行を返し、
  main が組み立てて egress ビルドを直列で実行する。正しいが、ビルドが 1 コアに
  戻り、すべての行が main 向けにコピーされる（N→1 のファンネル）— Phase E が
  取り除いた単一コアの上限を再導入する。
- **A2 — シャードが自分のスライスをビルドして送る（推奨）。** セッション
  ごとの `SyncCtx` スナップショット（next-hop-self 用のローカルアドレス、
  peer_type/AS、AddPath フラグ、out-policy スナップショット — `PolicyReplace`
  で既にシャードに複製済み — ENHE、クローン可能な `packet_tx`）がリクエストに
  乗る。各シャードが *自分の* スライスを変換 + out-policy フィルタ +
  エンコード + ピアへ直接送信し、全 N シャードコアにわたって完全なデータ
  局所性で並列に行う（gather コピーなし）。main は N-ack バリア（C.3 の
  broadcast-and-ack）の後にのみ EoR を出す。これは E.2+ の
  shards-as-update-workers モデルを read パスに適用したもの。ダンプを約 N 倍に
  スケールさせる唯一のオプションであり、AddPath のために候補テーブルを読む
  唯一のオプションでもある。1 つの `DumpV4` が `show`、`sync`、`clear` を
  すべてまかなう。
- **B — main の best-path ミラー。** reduce が `selected` を `bgp.shard.v4`
  にも書き込み、read は同期のまま。小さいが、ビルドは依然として main 上で
  直列、AddPath 同期は best-path のみのまま、そして FIB サイズの v4 コピー +
  常時のミラー整合性不変条件を再導入する — シャーディングが取り除いた
  まさにそのバグクラス。

**推奨: A2** — 完全に正しく *かつ* スケールする唯一の修正: 高価な egress
ビルドが 1 コアにファンネルバックする代わりにシャードコアにファンアウトする。
A1/B は正しいが直列（よくて単一 PR の応急処置）。マルチコアスケーラビリティの
ランキング: **A2 ≫ A1 ≈ B**。

トレードオフ: A2 はシャードごとに UPDATE をパックするため、異なるシャードに
ある同一属性のルート（属性はハッシュキーではない）は別々の MP_REACH
メッセージに乗る — わずかにパケットが増えるが、大きなダンプでは N 倍の CPU
利得が支配的。注意点（E.2 の教訓）: N ≈ コア数では、シャード内でビルドする
同期バーストが定常状態の ingest と競合する。ingest を飢えさせるなら、A2 の
ビルドを rayon のグローバルプールではなく上限付き `egress_pool()` 経由で
ルーティングする。

**PR 分解（A2）:** **Phase 0 + セッション確立時の `DumpV4` 同期パスは完了
してライブ（2026-06-16）。** `SyncCtx` は完全に `&Peer` フリー — out-policy
（`Arc<OutPolicy>`、キャッシュ済み）+ egress シンク
（`packet_tx`/`egress_depth`/`extended_message`）で、`route_update_ipv4`、
`route_apply_policy_out`、`send_ipv4_direct` がすべて `&SyncCtx` 上にある。
その上に: `ShardMsg::DumpV4 { req_id, Arc<SyncCtx>, params }` + `DumpDoneV4`
ack + `DumpBarrierV4` のリクエストごとバリア。シャードの `handle_dump_v4` が
自分のスライスを歩いて `SyncCtx` ごとにビルド + 送信し（Tier-1b park）、
main が `adj_out` デルタを記録して EoR を出す。そして `route_sync_ipv4` が
N>1 でそれを通るよう配線された — そこのカーソルを上書きし、B.4 のミラーでは
なく *権威ある* シャードスライスを読む（カーソルは N=1 で維持）。AddPath
送信は `@bgp_shard_addpath_v4` でカバー。N>1 シャード BDD 行列はグリーン
（88 シナリオ）。残作業: `show bgp ipv4` を `DumpV4` 経由に配線する（z2
アサーションをグリーンにする。ストリーム化 `show` のフォローアップと組で）→
`clear`/soft-in を同じ `DumpV4` に載せ替える。

### シャード同期行列 — 全 AFI/SAFI × AddPath 検証済み（B.4 完了、2026-06-15）

**ステータス（着地済み、ブランチ `bgp-shard-sync-matrix`、
`bgp-nshard-policy-shard` に統合）。** セッション確立時の同期パスは今や N>1
（4 シャード）で完全なファミリ行列にわたって BDD でロックされている。各
フィーチャは **sync → per-path withdraw → peer-down** を *遅延* ピア — ルートが
既に存在した後にのみ確立し、`route_sync_*` 経由でしか学習できない（イベント
駆動パスはそれらを配信できていない）ピア — に対して駆動する:

| ファミリ | sync | AddPath | BDD タグ |
|---|---|---|---|
| IPv4 unicast | ✓ | ✓ | `@bgp_shard_v4_sync` / `@bgp_shard_addpath_v4` |
| IPv6 unicast | ✓ | ✓ | `@bgp_shard_sync_v6` / `@bgp_shard_addpath_v6` |
| Labeled-unicast v4 | ✓ | ✓ | `@bgp_shard_sync_lu` / `@bgp_shard_addpath_lu4` |
| Labeled-unicast v6 | ✓ | ✓ | `@bgp_shard_sync_labelv6` / `@bgp_shard_addpath_lu6` |
| VPNv4 | ✓ | ✓ | `@bgp_shard_sync_vpnv4` / `@bgp_shard_addpath_vpnv4` |
| VPNv6 | ✓ | ✓ | `@bgp_shard_sync_vpnv6` / `@bgp_shard_addpath_vpnv6` |

**ディスパッチのスコープ — ミラーがそもそも適用されるファミリ。**
**プレーンな IPv4 unicast のみ** がプール分散される（`ShardMsg::RouteBatchV4`、
prefix でハッシュ）ため、read レプリカミラーを必要とする唯一のファミリである。
v6-unicast、LU-v4/v6、VPNv4、VPNv6 は **main の `bgp.shard` で同期 ingest**
される（プール化されない）ため、それらの Loc-RIB は N>1 でも埋まったままで、
`route_sync_*` はそれらを直接読む — ミラー不要。AddPath はどのファミリが
プール化されるかを変えない（AFI/SAFI ごとの決定）。AddPath フィーチャは、
`route_sync_*` が *すべての候補* を（`*.0` から）ダンプすること、そして
プール化 v4 のミラー（`BgpShard::mirror_v4`）が best パスだけでなく両候補を
保持することをピン留めする。

**sync 後 withdraw の `adj_out` 修正（一般的、シャーディング固有ではない）。**
遅延ピアに prefix をダンプする `route_sync_*` は、それを `peer.adj_out.<af>`
にも登録しなければならない。さもないと後のイベント駆動 withdraw の Adj-RIB-Out
ゲートがそのピアをスキップし、ルートがリークする。`route_sync_ipv6` と
`route_sync_labelv4`/`labelv6` でこれが起きた（修正済み）。
`route_sync_ipv4`/`vpnv4`/`vpnv6` は既に登録していた。per-path withdraw
シナリオがこれを行列全体でロックする。

**VRF 自己起源ネットワークの withdraw — 根本原因特定 + 修正（コミット
`541920a1`、`3941398c`）。** VPNv4/VPNv6 フィーチャで表面化した: `router bgp
vrf …` 設定から `network` を削除しても withdraw が出なかった。根本原因 —
`compute_vrf_diff` は VRF の *名前集合* のみを diff する（spawn/despawn を
駆動する）が設定本体は一切見ないため、*既に動いている* VRF への `network`
変更は desired config だけを更新し、VRF タスクはルートを永遠に advertise し
続けた（そして spawn 後に追加しても何も起きなかった）。自己起源 VRF
ネットワークは事実上不死だった。修正: 新しい
`BgpVrfMsg::{Originate,Withdraw}Network{,V6}` を設定コールバックから稼働中の
VRF にメッセージし、それが Loc-RIB で originate/withdraw して
`Export`/`WithdrawExport` を出す。`materialize_self_originated_networks` を
factor して prefix ごとのパスを正確に共有させ、spawn 時と動的起源が同一に
なるようにした。`afi-safi ipv4`/`ipv6` は presence コンテナなので、ブロック
全体を落とすとコンテナレベルの delete も出る。そのため `config_vrf_afi_ipv4`/
`ipv6` もネットワークを withdraw する（per-network パスと冪等）。
シャーディングとは独立 — 行列がたまたま露呈した潜在的な N=1 バグだった。

**注 — AddPath VPN テストトポロジ。** VPNv4/VPNv6 の AddPath は、*同じ*
NLRI（同じ RD+prefix）を起源とする 2 つの PE を必要とする。共有 import RT が
あると各 PE が相手のルートを再 import するため、一方の自己起源を withdraw
すると import したコピーが正しく *再 export* される — VRF として正しい挙動
だが、クリーンな単一パス withdraw アサーションには不向き。AddPath VPN
フィーチャは **export 専用 RT**（独立した起源）を使い、各パスを正確に 1 つの
PE に帰属させ続ける。

### 再開可能なセッション確立同期カーソル + egress バックプレッシャ（Tier 1a/1b、2026-06-15 構築）

B.4 のミラーは N>1 の v4 同期の *正当性* を修正した（ダンプすべきルートが
そこにある）。このペアはダンプ自体の *コスト* を修正する: ワンショットの
`route_sync_ipv4` は v4 Loc-RIB 全体を main タスク上で単一の中断のないパスで
ビルド + エンコードするため、新規ピアがその間 ingest とその他すべてのピアを
head-of-line ブロックする。両方とも env ゲート。**未設定 ⇒ レガシーの
ワンショットパス、完全な no-op。** ブランチ `bgp-sync-cursor-backpressure`、
`bgp-nshard-policy-shard` に統合。

**Tier 1a — 再開可能カーソル（`ZEBRA_BGP_SYNC_CHUNK`）。** Established 時、
`route_sync` が v4 prefix の *キー* をピアごとの `Ipv4SyncCursor` に
スナップショットする。イベントループがそれを tick ごとに `chunk` 個の prefix
ずつ駆動し（専用の *上限なし* `sync_tick` チャネル + `select!` アーム）、
チャンク間で ingest / 他ピアに譲る。各チャンクは *ライブ* の Loc-RIB を読み
（キーのみのスナップショット ⇒ 古い attr を読むことはない）、各送信を
`adj_out` に対して dedup する（interning ⇒ 等しい attr はポインタ等価）ので、
並行するイベント駆動 advertise パスと安全に競合する — どちらも `adj_out` を
ライブテーブルへ収束させるだけ。これは BIRD の `feed_index` +
`MAYBE_DEFER_TASK` モデル（§11）を zebra-rs の単一 main タスクに適用したもの。
キーのみは、レガシーのフルな `(prefix, BgpRib)` クローンより安価でもある。

計測 — main ループの最大連続占有時間（= head-of-line ブロック境界）、
chunk 500:

| RIB | ワンショット（off） | カーソル（on） | 削減 |
|---|---|---|---|
| 8 192 | 6.86 ms | 0.59 ms | 12× |
| 81 920 | 75.46 ms | 0.83 ms | 91× |

ワンショットの停止は N に **線形**（約 0.9 µs/route → ルートリフレクタの
1M で約 0.9 s）。カーソルのそれは **フラット** — RIB サイズではなくチャンク
サイズで律速 — なので利得はスケールとともに拡大する。総ビルド CPU は同等
（キーごとの trie ルックアップは bounded-working-set の局所性で相殺される）。
`@bgp_sync_cursor_v4` がチャンク配信 + EoR + `adj_out` dedup の withdraw /
peer-down を遅延ピアに対してピン留めする。

**Tier 1b — 上限付きバックプレッシャ（`ZEBRA_BGP_SYNC_EGRESS_HIGH`、
デフォルト 64）。** カーソルは依然としてすべての UPDATE を上限なしの
`packet_tx` にキューするため、*遅い* ピアがあるとダンプがメモリに溜まり得る。
ピアごとの in-flight ゲージ（`Peer::egress_depth`）— UPDATE がキューされた
瞬間に `send_packet` でインクリメントされ、書き込み時に writer で
デクリメントされるので **リアルタイム** — が、`drive_sync_v4` に watermark を
超えたらカーソルを park させ（sync-tick チャネル経由で再ポーリング）、writer が
ドレインするまで待たせることで、in-flight キューを上限化しダンプをピアの
ドレインレートに合わせる（BIRD の resume-on-writable、§11）。詰まったピアは
hold タイマがセッションを落とすまで park したまま — 正しい。読んでいない
ピアにダンプし続けてはいけない。

最初の実装は writer から `packet_rx.len()` を公開したが、これは writer が
遅い（書き込み中）まさにそのときに古くなるため一度も発動しなかった —
スロットルされたピアの BDD がそれを捕らえた。`@bgp_sync_backpressure` は
egress writer を遅くし（`ZEBRA_BGP_WRITER_DELAY_MS`、テスト/デバッグノブ）、
キューが決定論的にバックアップするようにし、park が発動すること（デーモン
ログ）と遅くなったダンプが依然として収束すること（フル RIB、最初の prefix
から最後まで）をアサートする。

**先送り。** IPv4-unicast のみ（v6/LU/VPN は同期 `route_sync_*` を維持）。
`show` RPC の 4 MB 上限 — テーブル全体を 1 メッセージに *ソート済み* で
ビルドするため、ストリーム化/ページネーション `show` は sorted-trie-resumable
のフォローアップ。そして **A2** — *ピア内* のシャード並列ダンプ（BIRD も
GoBGP も試みていない直交軸、§11）。

### Egress: N>1 での update-group flush ↔ シャードデルタ

ingress プールは prefix で *外向き* にファンする。egress は属性で *内向き* に
ファンする。両者は main イベントループで出会う。そこではグループごとの
キャッシュ（`cache_ipv4`、`Arc<BgpAttr>` でキー付け）が、N シャードの並列・
非同期な `BestPathV4` デルタを 1 つの合体された UPDATE flush に再収束させる
バッファである:

```
 N>1 · IPv4 unicast · shard deltas ──► update-group flush
 ═══════════════════════════════════════════════════════════════════════════

 shard-0 ─┐  BestPathV4 deltas — ASYNC, interleaved, one ShardResult/msg
 shard-1 ─┤  (each shard finishes its slice independently →
   ...    │   arrival order ≠ dispatch order)
 shard-N-1┘
            │
            ▼  main event loop : shard_results_rx
  ┌──────────────────────────────────────────────────────────────────────┐
  │ process_shard_result → route_apply_bestpath_v4_batch  (per delta):      │
  │    mirror_v4 + FIB install                                              │
  │    advertise: compute_advertise_outcome (OUT-POLICY)                    │
  │              peer.adj_out.add                                           │
  │              send_ipv4 → GROUP.cache_ipv4[Arc<attr>] += nlri  ◄─COALESCE │
  │              arm adv-interval debounce timer (first send)               │
  └──────────────────────────────────────────────────────────────────────┘
            │   deltas from ALL shards bucket into the SAME per-group cache,
            │   keyed by attr  →  one flush can carry NLRI from many shards
            ▼   timer fires → Message::FlushUpdateGroupIpv4
  ┌──────────────────────────────────────────────────────────────────────┐
  │ flush_ipv4:  cache.DRAIN() → FlushJob (snapshot);  flush_inflight=true   │
  │              tokio::spawn_blocking( job.run() )  format 1 UPDATE/bucket   │
  └──────────────────────────────────────────────────────────────────────┘
            │                                         ▲
   IN FLIGHT — more shard deltas keep arriving:       │ FlushDoneIpv4(counters)
     • ANNOUNCE → fresh (drained) cache ──────────────┼──► carried by NEXT flush
     • timer refires      → flush_pending = true       │
     • WITHDRAW of a prefix in the in-flight snapshot: │
         withdraw_ipv4_deferrable sees flush_inflight  │
         → PARK in deferred_withdraw_ipv4 (NOT sent)   │
            │                                          │
            ▼                                          │
  ┌──────────────────────────────────────────────────────────────────────┐
  │ flush_done_ipv4:                                                        │
  │   replicate formatted bytes → each member peer's packet_tx              │
  │       (split-horizon prunes the source member via source_ident)        │
  │   flush_inflight = false                                                │
  │   replay deferred_withdraw  — AFTER announces enqueued ⇒ ordered        │
  │       skip if peer.adj_out re-acquired the prefix (newer announce won)  │
  │   if flush_pending → flush_ipv4 again  (drains the new deltas)          │
  └──────────────────────────────────────────────────────────────────────┘
```

これが保つ不変条件:

- **キャッシュがシャードのファンアウトを再マージする。** 1 つのピアの prefix
  群は *すべての* シャードにハッシュ分散するため、flush された 1 つの UPDATE は
  日常的に複数の異なるシャードから返ってきた NLRI を運ぶ。`Arc<BgpAttr>` で
  キー付けされたグループごとのキャッシュがまさにそれらが再収束する場所である。
- **flush は N 非依存。** それは *best-path デルタのストリーム* を消費し、
  それがインラインシャード（N=1、`reduce_bestpath_v4_nht_fib`）から来たのか
  プール（N>1、`shard_results_rx`）から来たのかを一切知らない。シャーディングは
  到着をよりバースト的/インターリーブにするだけで、adv-interval の debounce +
  `cache.drain()`（`update_group.rs:787`）が N=1 とまったく同じようにバーストを
  1 つの flush に吸収する。egress 合体のセマンティクスは N で変わらない。
- **ドレインされたスナップショット、in-flight ジョブは 1 つ。**
  `build_flush_job_ipv4` がキャッシュをドレインするので、`FlushJob` は
  スナップショットを所有し、キャッシュは即座に新しいデルタを受け付けられる。
  グループごとに高々 1 つのジョブが動く（`flush_inflight_ipv4`）。flight 中に
  タイマが再発火すると `flush_pending_ipv4` をラッチし `flush_done` が再実行
  する — 並行するシャードデルタが、メンバの writer 上でバイトをインターリーブ
  し得る 2 つ目のジョブを spawn することはない。
- **クロスシャード withdraw レース — 処理済み。** in-flight ジョブが announce
  中の prefix に対する withdraw デルタ（*どの* シャードからでも）は、その
  announce をワイヤ上で追い越してはならない。`withdraw_ipv4_deferrable`
  （`route.rs:3741`）は `flush_inflight` を見て withdraw を
  `deferred_withdraw_ipv4` に park する。`flush_done_ipv4` はすべての announce
  バイトがエンキューされた後にのみそれを replay し、`adj_out` がより新しい
  announce が prefix を再取得したことを示せばスキップする。異なる時刻の異なる
  シャードメッセージから来ても announce-before-withdraw の順序が保たれる。
- **prefix ごとの順序が保たれる。** 各 prefix はちょうど 1 つのシャードに
  住むので、その add→withdraw シーケンスはそのシャードのキューを順に通り、
  main に順に届く。deferred-withdraw 機構がワイヤ上でそれを保つ。prefix 間の
  順序は BGP の正当性には無関係。
- **flush はシャード状態に触れない。** それは main 側の構造のみを読む —
  グループキャッシュと、ビルド時にキャプチャした各メンバの
  `packet_tx`/`adj_out`。シャードの唯一の egress 役割は delta→advertise
  ステップ経由でキャッシュを供給することである。フォーマット + 複製は main +
  blocking プール上で動く。

つまり ingest は prefix でシャード間に外向きにファンし、egress は属性で
ピア間に内向きにファンし、両者は main イベントループで出会う。そこで
グループごとのキャッシュが、インターリーブされたマルチシャードデルタの
バーストを 1 つの合体され正しく順序づけられた UPDATE flush に変える
ショックアブソーバである。

## 1. 結論

Juniper の BGP RIB シャーディングは zebra-rs に適用可能である — そして
zebra-rs は RPD よりも構造的にそれに適した位置にある。Juniper の設計原則は
「ロックなし、メッセージパッシング、スレッドごとの状態所有、結果整合性」で
あり、これは既に zebra-rs のネイティブな流儀（tokio タスク + チャネル）で
ある。適用可能な形態は **prefix ハッシュで分割されたシャードタスク + 既存の
update-group キャッシュで供給される update-worker タスク** であり、既存の
単一イベントループはセッション/協調タスクとして保持する。

Juniper が解かねばならなかった最も難しい集中化問題のいくつか（リゾルバ
サービス、FIB ダウンロード、クロスプロトコルのアクティブルート選択）は、
BGP が中央 RIB デーモンから分離されているため、zebra-rs では既にチャネル
ベースのサービスとして存在する。本当のコストは並行性の機構ではなく —
`Bgp` 構造体の状態を shard-owned / replicated / main-only クラスに分割する
ことである。

## 2. Juniper が作ったもの

2 つのスレッドファミリ、加えてレガシーの main スレッド:

- **シャードスレッド（S1..Sn）** — RIB は *prefix アドレスのハッシュ* で
  スライスされる。各シャードは自分のスライスをエンドツーエンドで所有する:
  inbound flash、ポリシー、best-path 選択 — スレッドごとの状態とクロス
  シャード同期ゼロの「ミニエコシステム」。非 BGP ルートもシャードにハッシュ
  されるので、ある prefix の *すべての* ルートはちょうど 1 つのシャードに住む。
- **update スレッド（U1..Um）** — シャードは UPDATE メッセージを直接出さない
  （それはシャード間でパッキングを断片化する）。代わりに **Route Tuple
  Object（RTO）** — prefix + 属性の短縮形 — を出し、update スレッドが全
  シャードからの RTO を効率的にパックされたグループごとの UPDATE にマージする。
- **main スレッド** — 集中ビューを必要とするすべて: ネクストホップ解決
  （シャードが消費する「サービスとしてのリゾルバ」）、条件付きポリシー、
  IGP export、FIB ダウンロード（KRT）。

公開結果: 24 コアのルートリフレクタ（in 8M ルート / out 800M）で収束 約 9 倍、
peering/flap シナリオで 3.5–4 倍、4 コアのエッジボックスで 2.5 倍。利得は
**RIB-FIB 比**（一意 prefix あたりに学習するパス数）と outbound のファンアウト
でスケールし、prefix ごとの main スレッド作業（FIB install）が支配的になる
場合やルート規模が小さい場合には蒸発する。最適スレッド数 <= CPU コア数。

## 3. zebra-rs の現状 — 直列化の単位

ルート処理パイプライン全体は 1 つの tokio タスク（`event_loop`、
`zebra-rs/src/bgp/inst.rs:2959`）で動く。既に並列なものとそうでないもの:

| ステージ | 現状 | 場所 |
|---|---|---|
| Wire parse | 並列、ピアごとの reader タスク | `bgp/peer.rs:2065`、`peer_packet_parse` |
| Policy-in、attr intern、Adj-RIB-In | main ループで直列化 | `bgp/route.rs:2185-2201` |
| Loc-RIB insert + best path | 直列化 | `bgp/route.rs:990`、`select_best_path` は `bgp/route.rs:1039` |
| NHT ゲート / 再選出ストーム | 直列化 | `set_nexthop_reachable` スイープ |
| VRF import/export ファンアウト | 並列、VRF ごとのタスク、チャネルベース | `vrf_emit_export` / `dispatch_import_v4`、`bgp/route.rs:2258-2294` |
| Advertisement バケット化 | 直列化 | グループキャッシュ、`bgp/update_group.rs:181` |
| UPDATE エンコード | 直列化（ただし既に **グループごとに 1 回**、メンバへ複製） | `bgp/update_group.rs:640-667` |
| TCP write | 並列、ピアごとの writer タスク | `bgp/peer.rs:2075` |

パイプラインは両端で並列、中央でシングルスレッド。マシンサイズに関係なく
1 コアが収束の上限である。

## 4. 構造的マッピング — なぜこれが異例なほどよく適合するのか

| Junos の概念 | zebra-rs の対応物 | ステータス |
|---|---|---|
| RIB スライスを所有するシャードスレッド | `BgpShard` が `LocalRibTable<P>` パーティション + adj-in スライスを所有（N=1 ではただのフィールド、N>1 ではシャードごとの専用 OS スレッド — tokio タスクでは *ない*） | ✅ 構築済み — プレーンな v4-unicast のみがプール全体にファンアウトする。VPNv4（transit ラベルが main の中央アロケータを必要とする）、v6、VPNv6、LU の best-path は依然として単一の同期シャード上で動く。VRF ごとのタスク（`process_vrf_global_msg`）が先例で、ハッシュではなくテーブルでシャード化していた |
| RTO（prefix + attr 短縮形） | `(Arc<BgpAttr>, Nlri, source_ident)` — *既存の* update-group キャッシュエントリ（`bgp/update_group.rs:181`） | 存在する — zebra-rs は RTO を名付けずに発明していた |
| RTO をパックする update スレッド | `UpdateGroup` キャッシュ + debounce タイマ + 正規エンコードを所有する update-worker タスク | 🔶 部分的 — エンコードはスレッド外（A.2 `FlushJob` → `spawn_blocking`）で、out-policy 事前計算は並列化（E.1/E.2 上限付き egress プール）。`AdvDelta` を供給される専用グループ親和性ワーカーは依然として将来（E.2+、§12） |
| main 内のサービスとしてのリゾルバ | 既にサービス: RIB デーモンの NHT を `RibRx::NexthopUpdate` チャネルで | 存在する |
| シャードにハッシュされる非 BGP ルート | **不要** — クロスプロトコルのアクティブルート選択は BGP ではなく中央 RIB デーモンに住む | Junos より単純 |
| main からの KRT/FIB ダウンロード | `rib_client` チャネルが送信 — ハンドルはシャードにクローン可能 | 存在する |
| タスク間の属性転送 | `BgpVrfMsg::ImportV4 { attr: BgpAttr, .. }` — attr を値で渡し、受信側が自分の `BgpAttrStore` に再 intern する（`bgp/vrf/msg.rs:37-40`） | 規約が既に確立されている |
| スレッドごとの状態局所化 | Rust の所有権 — RPD が規律で維持せねばならなかったパーティションをコンパイラが強制する | 利点 |

## 5. 目標アーキテクチャ（最終状態）

```
peer reader tasks ──Event──▶ ┌──────────────┐
                             │  main task   │  FSM, config, show fan-out,
peer writer tasks ◀──bytes── │ (coordina-   │  listeners, VRF registry,
        ▲                    │  tion)       │  NHT RIB-facing session,
        │                    └──┬───────┬───┘  FIB install, small tables
        │            RouteBatch │       │ control (policy / peer events /
        │            (per-NLRI  │       │ NHT replicas / refresh / sync)
        │             hash)     ▼       ▼
        │                  ┌────────┐ ┌────────┐
        │                  │shard 0 │…│shard N │  policy-in, adj-in slice,
        │                  └──┬─────┘ └──┬─────┘  Loc-RIB slice, best path,
        │           AdvDelta  │          │        VPN import/export emit
        │           (RTO)     ▼          ▼   FibDelta ──▶ main ──▶ RIB
        │                  ┌────────────────┐
        └──── encoded ──── │update workers  │  per-group transform, bucket,
              UPDATEs      │ 0..M (group    │  debounce, canonical encode,
                           │  affinity)     │  adj-out
                           └────────────────┘
```

- **シャード所有**: v4/v6 unicast、v4/v6 labeled-unicast、VPNv4/v6 テーブル、
  加えてそれらのテーブルの (peer, prefix) ごとの adj-in スライス。
  *内側の* prefix アドレスのみでハッシュするので、1 prefix の unicast/LU/VPN
  インスタンスが同居する（Juniper の不変条件）。
- **main に残るもの**: `PeerMap` + FSM、listeners/accept、config/show
  ディスパッチ、`nexthop_cache`（RIB 向け登録。シャードはレプリカを保持）、
  FIB 発行、VRF registry + label/SID アロケータ、redistribute スナップ
  ショット、そして小さなテーブル: EVPN、flowspec、SR-Policy、BGP-LS、RTC、
  table-map。
- **シャードに複製されるもの**（変更時にブロードキャスト）: ポリシー
  スナップショット、NHT エントリ（到達性 + 解決済みトランスポート）、
  `rib_known_vrfs` からの import-RT 集合、VRF inbox sender、シャードごとの
  ラベルサブブロック。
- **VRF ごとのタスク** は外側の次元として残り、当初は単一シャード。

## 6. ステップバイステップの提供計画

各 PR は `main` から分岐した別ブランチ（リポジトリ規約）で、CI グリーンの
ときのみ着地し、デーモンを完全に機能する状態に保たねばならない —
シャーディングは C.4 が YANG ノブを切り替えるまでデフォルト off で出荷される
（`ZEBRA_BGP_SHARDS` 未設定 → N=1）。ステータス列は `bgp-nshard-policy-shard`
ブランチを反映する（A 以降の全行は 2026-06-14 時点で未マージ）。

| ステップ | タイトル | 依存 | ステータス |
|---|---|---|---|
| 0.1 | ベンチハーネス + ベースラインプロファイル | — | マージ済み（PR #1406） |
| A.1 | Flush ジョブ抽出（純粋関数） | — | マージ済み（PR #1408） |
| A.2 | Flush をワーカーへオフロード | A.1 | マージ済み（PR #1416） |
| B.1 | 状態分割: `BgpShard` 構造体、adj-in 再キー化 | — | ✅ 構築済み（WIP ブランチ） |
| B.2 | シャードメッセージプロトコル + ラベルサブブロック | B.1 | ✅ 構築済み（WIP ブランチ） |
| B.3 | ~~シャードタスクを spawn~~ → **同期ディスパッチ** at N=1 | B.2 | ✅ 構築済み — 同期に方針転換、「実装ステータス」参照 |
| B.4 | Show / clear / sync scatter-gather | B.3 | ❌ 未構築 — `show` / `sync` / `clear` がすべて N>1 で空の `bgp.shard.v4` を読む（`@bgp_shard_v4_sync` 赤）。推奨 A2 修正計画は実装ステータスに |
| B.5 | N=1 での BDD + ライフサイクル硬化 | B.4 | ⏳ |
| C.1 | prefix ハッシュで N シャードへファンアウト（+ YANG ノブ） | B.5 | ✅ 構築済み — 専用スレッド `ShardPool`、env ゲートの `ZEBRA_BGP_SHARDS`（プレーン v4-unicast のみ。VPNv4/v6/VPNv6/LU は依然同期）。YANG ノブは依然将来 |
| C.2 | update-worker タスク（グループ親和性） | A.2, C.1 | 🔶 部分的 — E.1/E.2 並列 egress（上限付きプール）構築済み。専用グループ親和性ワーカー = E.2+（§12） |
| C.3 | バリア: EoR、refresh、GR/LLGR スイープ、clear | C.1 | ⏳ |
| C.4 | 性能行列、デフォルト、ドキュメント | C.2, C.3 | ⏳ |

> **Phase C ラベル注記**: 「C.1/C.2」は 2 つの異なる軸を指す。*再スコープ後*
> の C.1/C.2（N=1 での rayon 並列 inbound/outbound **ポリシー**）が最初に
> 構築された。*元計画* の C.1（マルチシャードファンアウト）はその後、専用
> スレッド `ShardPool` として着地し、元計画の C.2（update-worker）は E.1/E.2
> の並列 egress で部分的にカバーされ、専用グループ親和性形態は E.2+（§12）に
> 先送りされた。上記の行は元計画の軸を追う。

### Phase 0 — ベースライン計測（何かに触れる前に）

**0.1 — ベンチハーネス + ベースラインプロファイル。**
zebra-rs に対して N 個の BGP セッションを開き、M ルートをぶつけ（エンコードに
`bgp_packet` crate を再利用）、(a) Loc-RIB 静定までの時間と (b) リスニング
セッションでの再 advertise までの時間を計測する負荷生成器。加えて、負荷下の
main タスクの flamegraph レシピをドキュメント化する。ベースライン数値を本書に
記録する。
*なぜ最初か*: Juniper の利得は時間が実際にどこに行くか（ポリシー/best-path
vs エンコード/ファンアウト vs アロケーション）に依存する。プロファイルが
期待値を見積もり、Phase C のデフォルトを選び、後続の全ステップが通らねば
ならない回帰ゲートになる。
*Exit*: §9 のベースライン表。ハーネスは CI が要求時に実行可能（デフォルト
スイートには含めない）。

### Phase A — Update-flush オフロード（シャーディングと独立）

**A.1 — Flush ジョブ抽出。**
`flush_ipv4`（`bgp/update_group.rs:492`）は既にエンコード前にバケットを
ドレインし `MemberCtx { ident, packet_tx, enhe_v6, llgr_ok }` を
スナップショットしている — その分割を明示的にする: `FlushJob` 値（バケット、
member ctx、`max_packet_size`、sig 由来の定数）と純粋な `run(job) -> (メンバ
ごとのバイトバッチ、カウンタデルタ)`。main は依然インラインで実行する。
`flush_ipv6` も同様。
*テスト*: 正規 + プルーニング済み UPDATE エンコードをピン留めするゴールデン
バイトテスト（attr バケットごと、split-horizon ソースあり/なし、LLGR 除外、
メンバごとの ENHE ネクストホップ）。挙動変更なし。

**A.2 — Flush オフロード。**
`FlushJob::run` を `tokio::task::spawn_blocking`（IS-IS SPF オフロードの
先例）上で実行する。バイトはワーカーからスナップショットされた `packet_tx`
sender へ直接送られる。カウンタデルタは新しい
`Message::FlushDone(group_id, deltas)` 経由で返る。不変条件: **グループ
ごとに in-flight な flush は高々 1 つ** — `UpdateGroup` の `flush_inflight`
フラグ。flight 中にキューされたルートは `FlushDone` で debounce タイマを
再武装する。
*テスト*: A.1 ゴールデン不変。BDD スイートグリーン。ベンチがファンアウト
ワークロード（多メンバ、大テーブル）で main ループの余裕を示す。

### Phase B — N=1 でのシャード抽出（本当のリファクタ、レースフリー）

**B.1 — 状態分割（機械的、単一タスク、挙動変更なし）。**
`struct BgpShard` を導入し、シャード所有の状態をそこに移す:
`local_rib.{v4,v6,v4lu,v6lu,v4vpn,v6vpn}`、シャード側 `BgpAttrStore`、
adj-in。adj-in は今日 `Peer` に住む（`peer.adj_in.add`、
`bgp/route.rs:2187`）— `Peer` は main 所有のまま残るので、これを
`ident -> AdjRib` スライスとしてシャードに再キー化する。既存の
`BgpInstCtx` 借用バンドル（`bgp/inst.rs:2940-2953`）が継ぎ目になる:
それを `ShardCtx`（`route.rs` 関数が触ってよいすべて）と main 専用コンテキスト
に分割し、`route.rs` のエントリポイントを `&mut BgpShard` を取るよう再ホーム
する。監査はコンパイラが行う — route パスから main 専用状態へのあらゆる
アクセスがビルドエラーになり、意図的に解消する。EVPN/flowspec/SR-Policy/
BGP-LS/table-map は明示的に `BgpShard` の外に留まる（§8 D3 参照）。
*レビュー時にありそうな分割*: adj-in 再キー化（B.1a）vs `ShardCtx` 抽出
（B.1b）。本シリーズ最大の機械的 PR。
*テスト*: フルスイート + A.1 ゴールデン。機能デルタゼロ。

**B.2 — シャードメッセージプロトコル + シャードごとのラベルサブブロック。**
`bgp/vrf/msg.rs`（ドキュメント化された先例）をモデルにする:
- `ShardMsg`（main → shard）: `RouteBatch { ident, afi_safi, attr,
  nlris }`、`WithdrawBatch`、`PeerUp { ident }` / `PeerDown { ident }`
  （flush + adj-in クリア）、`Originate`/`Deoriginate`（network +
  redistribute + BGP-LS 非依存のローカルルート）、`PolicyReplace`、
  `NexthopUpdate`、`RtSetsUpdate`、`VrfInboxUpdate`、`SyncPeer { ident,
  afi_safi }`（Established ウォーク / soft-out）、`Refresh { ident, op }`
  （soft-in リプレイ）、`Show(DisplayRequest)`、`Shutdown`。
- `ShardOut`（shard → main）: `FibDelta { table, prefix, selected }`、
  `NhtTrack`/`NhtUntrack`、`AdvDelta { afi_safi, prefix, best,
  source_ident }`（RTO — C.2 まで main の既存 advertise パスが消費）、
  `LabelBlockLow`（サブブロック補充要求）。
- VPN import/export はシャードから VRF inbox へ / VRF タスクから所有シャードへ
  **直接** 出す — チャネルハンドルはクローン。main ホップなし。
- ラベル割り当て（`lu_label_*`、`vpn_label_v4` — ホットパスの
  `bgp/route.rs:2223` で参照）はルートごとに main へ RPC できない:
  RIB が付与した動的ブロックをシャードごとのサブブロックに切り分け、
  シャードはローカルに割り当て、`LabelBlockLow` 経由で補充を要求する。
*テスト*: プロトコル型 + サブブロックアロケータの単体テスト。順序契約
（§7）を doc-comment 化する。

**B.3 — シャードタスクを spawn（N=1）。**
`spawn_bgp_vrf`（`bgp/vrf/spawn.rs:115`）をミラーする: `BgpShardHandle
{ inbox, show_tx, task }`。main は `FsmEffect::RouteUpdate` パケットを
`RouteBatch` として中継し（attr は reader タスクが既にパース済み）、
シャードが policy-in → intern → adj-in → Loc-RIB → best path → NHT
ゲートを実行し、`FibDelta`（main が `fib_install_*` 経由で install し、
table-map/color/flex-algo の参照を main に保つ）と `AdvDelta`（main が
今日の `route_advertise_to_peers` バケット化に供給する）を出す。Peer
up/down/refresh は制御メッセージとして中継する。ピアごとのスイープを
`BgpShard` 上の 1 つの `route_clean(ident)` API に集中させ、シャード化
された全 AFI/SAFI をカバーする — これは「新しい SAFI は route_clean ブロックを
追加し忘れてはならない」バグクラス（#1329）を構造的に閉じる。
*テスト*: フル BDD スイート（本当のゲート — すべての BGP フィーチャが分割を
通る）。中継パスの的を絞った単体テスト。

**B.4 — Show / clear / sync scatter-gather。**
ルートテーブルの show コマンドはシャードの show チャネルに移り、
`SubscribeShowVrf` リダイレクトレシピ（`BgpVrfHandle::show_tx`）を再利用する。
summary/neighbor show は main に残る。`clear bgp` の soft-in はシャード内で
adj-in をリプレイする。soft-out は `SyncPeer` を再実行する。hard clear =
`PeerDown` + セッションリセット。
*テスト*: BDD show/clear フィーチャ。移動した show スペルに対する `parse()`
ピンテスト。

**B.5 — ライフサイクル硬化 + N=1 での BDD。**
専用 BDD フィーチャ: 連続ルートチャーン下のピアフラップ、ストリーム途中の
route-refresh、EoR タイミング、GR/LLGR の stale スイープ — teardown 後に
リークしたルートがないことをアサート（§7 順序契約の実践）。
*Phase B の Exit*: N=1 でフル BDD グリーン。ベースラインとのベンチパリティ
（ノイズを超える回帰なし）。本書に計測した中継オーバーヘッドを更新。

### Phase C — N シャード + M update-worker（Juniper 形態）

**C.1 — prefix ハッシュファンアウト。**
`shard_of(prefix) = hash(内側 prefix アドレス) % N` — AFI/SAFI 間で安定なので
1 prefix の LU/VPN/unicast 行が同居する。main は各 `RouteBatch` をシャード
ごとに分割し（ハッシュ + Vec push のみ — 重い作業は既にシャード側）、制御
メッセージは全シャードにブロードキャストし、`SyncPeer` はファンアウトして
各シャードが自分のスライスを歩く。YANG ノブ `router bgp shards <1-64>`
（デフォルト 1）はインスタンスの（再）起動時のみ適用 — ライブ再シャーディングは
スコープ外。NHT: main がシャード間で `NhtTrack`/`NhtUntrack` をリファレンス
カウントし、単一の RIB 向け登録を保ち、`NexthopUpdate` レプリカをブロード
キャストする。
*テスト*: 既存のマルチピアフィーチャの shards=2 と 4 での BDD バリアント。
単体テスト: ハッシュ安定性 + 同居プロパティ。

**C.2 — update-worker タスク。**
`UpdateGroupMap` の所有権 + Phase A の `FlushJob` 機構を、**静的な group →
worker 親和性** を持つ M 個のワーカータスクに移す。シャードは `AdvDelta` を
所有ワーカーに直接送る（main をバイパス）。ワーカーは自分のグループの
メンバに対するグループごとの変換（Phase 2 のメモコード）、バケット化、
debounce タイマ、エンコード、adj-out を所有する。main は regroup と peer
Established 時にメンバシップ/sig スナップショットをブロードキャストする。
(peer, prefix) ごとの順序は保たれる: 1 prefix → 1 シャード → グループを
所有する 1 ワーカーへ FIFO。
*相互作用*: update-groups 設計の Phase 4（動的 regroup）は main → worker
ブロードキャストになる。#4 を先に着地させるかここに畳み込むか — レビュー時に
決める。
*テスト*: A.1 ゴールデンをワーカー境界で再ピン留め。BDD soft-out /
advertised-routes フィーチャ。

**C.3 — N>1 でのバリアとライフサイクル。**
EoR の発行は全シャードの同期完了を待つ（broadcast-and-ack）。route-refresh と
GR/LLGR の stale スイープも同様に ack ゲート。hard clear はセッション再起動
前にシャードごとのキューをドレインする。ベンチハーネスでのカオステスト:
shards=4 でフルテーブル負荷下のピアチャーン、後で Loc-RIB/adj-out の整合性を
アサート。

**C.4 — 性能行列 + デフォルト。**
Phase 0 の行列を shards × update-workers × peers × routes（Juniper の表を
テンプレートとして）で再実行する。結果を §9 に記録する。出荷デフォルトを
選ぶ（数値が反論しない限り 1 のまま — Juniper のデータは利得に RIB-FIB 比と
ファンアウトが必要だと言っており、我々自身のワークロードで証明すべき）。
`docs/` + book ページを更新する。それからデフォルト切り替えを検討する。

## 7. 正当性の不変条件

- **単一中継 FIFO 順序（v1）**: main が各シャードチャネルへの *唯一の*
  producer であり、FSM 順に中継する — だから 1 ピアの `RouteBatch`、
  `PeerDown`、`PeerUp`、`Refresh` は main が処理したのとまったく同じ順序で
  到着する。これが成り立つ間はエポック不要。後で main をバイパスするもの
  （例: reader 直接ディスパッチ、リストされたフォローアップ）は **必ず**
  ピアごとのセッションエポックとシャード側の stale エポック drop を導入
  しなければならない。
- **prefix ごとの順序**: 1 prefix → 1 シャード（ハッシュ親和性）→ 1
  update-worker（グループ親和性）→ ピアごとの writer FIFO。prefix 間の
  並べ替えは許容される — それは BGP が既に許容し Juniper の設計が依拠する
  結果整合性である。
- **グループごとに in-flight な flush は 1 つ**（A.2 から）— グループ内の
  announce/withdraw 順序を保つ。
- **broadcast-and-ack バリア** を EoR / refresh / GR スイープに（C.3）:
  すべてのシャードが ack するまでバリアは完了と宣言できない。
- **update-group シグネチャ規律** は変わらず、update-worker を安全にする
  ものである — `bgp-update-groups.md` §6 のリスク台帳（サイレントリーク、
  ケーパビリティ不一致）が同一に適用される。

## 8. 決定（解決済み）

4 つすべて推奨どおりに裁定され、現在のビルドに反映されている（Status
ヘッダ参照）: **D1** リポジトリ内 `bgp-bench`（PR #1406）。**D2** 当面
両方向で上限なしのチャネル、バックプレッシャは §12 P2 として追跡。
**D3** v4/v6-unicast + LU + VPNv4/6 をシャード化、EVPN/flowspec/SR-Policy/
BGP-LS/RTC は main 所有。**D4** デフォルトシャード数 1（`ZEBRA_BGP_SHARDS`
によるオプトイン）、計測された knee は N=4。各々の元々の枠組みは以下。

- **D1 — ベンチハーネスの形態（Phase 0.1）**: `bgp_packet` を再利用する
  リポジトリ内 Rust インジェクタ（推奨 — 新しいシステム依存なし、CI 実行可能）
  vs BDD ハーネスから GoBGP/exabgp を駆動（コードは少ないが環境が重く、
  エンコードレート制御が貧弱）。
- **D2 — チャネルの上限（B.2）**: VRF の先例に合わせることを推奨 —
  両方向で上限なし（`vrf_global_tx` スタイル）で main↔shard の send
  デッドロックを排除し、C.4 の数値後にバックプレッシャを再検討。代替:
  `try_send` + オーバーフロー計上付きの上限付きデータチャネル。
- **D3 — シャード化テーブルのスコープ（B.1）**: v4/v6 unicast + LU +
  VPNv4/v6 のみを推奨。EVPN（MAC ルートは IP prefix でハッシュしない、ESI の
  クロス依存）、flowspec、SR-Policy、BGP-LS、RTC は main 所有のまま —
  それらは小さなテーブルで、シャード化しても何も得られずパーティションを
  複雑にする。
- **D4 — デフォルトシャード数（C.4）**: 我々自身の性能行列が導出される
  デフォルト（例: `min(4, cores/2)`）を正当化するまで、出荷デフォルト 1
  （シャーディングはオプトイン）を推奨。

## 9. 性能記録

ハーネス: `tools/bgp-bench`（Phase 0.1、PR #1406）。方法論: N 個の eBGP
sender が同じ `--prefixes` 集合をぶつけ（RIB-FIB 比 = N）、2 個の eBGP
receiver が再 advertise を数える。収束 = blast 開始 → 最も遅い receiver で
最後の announce（3s の静寂窓、数値からは除外）。デーモン設定:
`no-fib-install true`、MRAI 1s 両ピアタイプ（±1s の量子化フロア）。

マシン: 以下の初期ベースライン表は 5-vCPU VM（モデル非公開）、31 GB RAM、
Linux 6.8.0-124-generic。12 コアの行列（実装ステータス §「計測」と以下の
base-vs-sharded スイープ）は後の 12 コア / 31 GB ボックス。flamegraph は保留:
`perf_event_paranoid=4` がこれらのボックスで非特権 perf をブロックし、user
namespace が制限されている — スレッドレベルの帰属には root 実行が必要
（レシピはベンチ README に）。§3 の単一タスク直列化の主張は今や「実装
ステータス」のワークロードプロファイルで裏付けられる: `PrefixTrie::
walk_enclosing` 74.8%（ポリシー負荷）、SipHash interning 約 28%、N=12 での
アロケータの `osq_lock` 約 12% — すべて単一コアのホットスポットで、ポリシー
並列化、シャーディング、アロケータ/ハッシャ交換が狙うもの。

ベースライン、分岐点 `41a1d07d`（2026-06-12）:

| senders × prefixes | paths in | 収束 | unique pfx/s | paths/s in | daemon RSS |
|---|---|---|---|---|---|
| 4 × 100k | 400k | 1.564s | 64.0k | ~256k | 789 MB |
| 8 × 100k | 800k | 4.556s | 21.9k | ~176k | 1.43 GB |
| 4 × 500k | 2.0M | 8.147s | 61.4k | ~245k | 3.69 GB |

観察: candidates-per-prefix が上がると path ごとのスループットが *下がる*
（8-sender 行）。4×500k 実行は 500k prefix に対し 1.17M NLRI を再 advertise
した — ingest 中に sender のパス間で best-path がフリップすることが egress
作業を概ね倍増させる。両方とも、シャード（prefix ごとの再選出）と
update-worker（egress エンコード）並列性が攻撃するまさにそのコスト。

ステップごとの結果（同じ行列）は A.2 / B.5 / C.4 完了時にここに着地する。
変更されていないベースラインバイナリで行列を再実行すると約 10% の
run-to-run ばらつきが見られた（announce 数は best-path フリップのタイミングで
2 倍変動する）ので、それ未満の単一実行デルタはノイズ。

| ステップ | 4×100k | 8×100k | 4×500k |
|---|---|---|---|
| Baseline | 1.564s | 4.556s | 8.147s |
| A.2（PR #1416、2 runs） | 1.64–1.76s | 4.65–4.70s | 7.55s |
| B.3 sync-dispatch（N=1） | パリティ ±noise | パリティ ±noise | パリティ ±noise |
| C.4（best） | | | |

A.2 の読み: 100k スケールではノイズ内でパリティ、2M paths で約 7%。想定どおり —
A.2 はグループごとのエンコードをオフロードし、そのコストはメンバファンアウト
でスケールするが、この行列は receiver が 2 つだけ。構造的な勝因は解放された
main ループ。egress 並列性が実際に効くのは C.2（update-worker）。

**B.3 sync-dispatch（N=1）の読み**: この *ポリシーなし* 行列は構築済みの
C.1/C.2 を示すには間違ったワークロードである — ルートごとの作業は intern +
best-path + エンコードでありポリシーではないので、`BgpShard::handle` 経由の
ルーティングはノイズ内パリティ（ディスパッチは同じコア、勝因はここには
なかった）。構築済みのポリシー並列化 C.1/C.2 は上の「実装ステータス」の
ポリシー負荷ワークロードで計測されている（12 コアで直列 19.57s → 4.34s）。
計画されたマルチシャード C.1 / update-worker C.2 こそ、この行列が捉えるべき
もの（構築されたら）。

**Base-vs-sharded スイープ（12 コア、8×500k ポリシーなし）— 2026-06-14、
HEAD `3a27ec65`。** 12 コアボックス（12 コア、31 GB、Linux
6.8.0-124-generic）での新鮮な back-to-back 実行: base はシャーディング前の
分岐点 `41a1d07d` から再ビルドし *同じ* `bgp-bench` バイナリで駆動、その後
現在のビルドで `ZEBRA_BGP_SHARDS` をスイープ（1 バイナリ、実行ごとにデーモン
再起動、各 3 runs）。ハーネスは上記どおり — 8 senders、2 receivers、500k
prefixes、`no-fib-install`、MRAI 1s。

| ビルド | r1 | r2 | r3 | avg | base 比 |
|---|---|---|---|---|---|
| base（シャーディング前 `41a1d07d`） | 22.29 | 22.51 | 23.31 | 22.70 s | — |
| N=1（同期ディスパッチ） | 17.28 | 16.37 | 17.42 | 17.02 s | −25% |
| N=4 | 14.29 | 14.88 | 14.09 | 14.42 s | **−37%（knee）** |
| N=12 | 16.56 | 15.18 | 17.85 | 16.53 s | −27% |

デーモン RSS 7.0 GB（base）→ 7.6 GB（N=12）。12 runs すべて収束。これは
以前の 12 コア行列（実装ステータス §「計測」）を再現する: N=4 の絶対値は
約 0.1 s で一致（14.42 vs 14.44）、N=12 は約 0.1 s（16.53 vs 16.61）。base は
このセッションで約 2 s 遅く走った（22.70 vs 以前の 20.73、約 10% の
run-to-run ばらつきの内）ので、相対デルタはわずかに大きく出る。2 つの
要点が成り立つ。**(1) N=1 が並列性なしで既に −25%** — 同期ディスパッチは
base と同じ単一 ingest スレッドなので、勝因はブランチのグローバル交換
（mimalloc アロケータ + `store.rs` の `ahash` attr-interning ハッシャ、両方
base には不在）であってシャーディングではない。**(2) シャードファンアウトが
約 12 ポイント加える**（N=1 −25% → N=4 −37%）、その後 N=12 で過剰シャード
（reduce + tokio I/O の予備コアなし）。AddPath 修正 `3a27ec65` はここでは
ベンチマーク中立（IPv4 負荷。v6/LU の advertise ループのみに触れる）。

## 10. 注意点 & スコープ外

- **利得には規模とファンアウトが必要**（高い RIB-FIB 比、多ピア）。
  2 ピアの BDD トポロジは利得ゼロまたは負を示す — それは想定どおり、BDD は
  正当性ゲート、§9 の行列が性能ゲート。
- **Phase C は Phase 0 プロファイルにゲートされていた — そしてプロファイルが
  それを裏付けた。** Interning（SipHash 約 28%）とアロケーション
  （`osq_lock` 約 12%）が確かに支配的だったので、両方をまずシングルスレッドで
  修正した（ahash + mimalloc、これだけで N=1 が base 比 −25% になる）後に
  シャードファンアウト — まさに計画が呼んだ「まずそれを修正」。
- **次のボトルネックは中央 RIB デーモンに移る**（単一タスク）、1:1 の
  RIB-FIB ロールで — ここではスコープ外、非 RR ロールのエンドツーエンド利得を
  束縛する。
- スコープ外: ノブ変更時のライブ再シャーディング、VRF ごとのタスク内部での
  シャーディング（それらは単一シャードのまま。機構は後で再利用可能）、
  reader 直接シャードディスパッチ（エポックが必要、§7）、RIB デーモン
  並列性、EVPN/flowspec/SR-Policy/BGP-LS のシャーディング。

## 11. 先行事例: BIRD 3.x と GoBGP の並列性

独自のメモに抽出: [`bgp-sharding-prior-art.md`](bgp-sharding-prior-art.md)。
BIRD 3.3.0（ブランチ `stable-v3.3`）と GoBGP（`master`）の両方を全読して
zebra-rs の設計を位置づけた — 鋭い問いは **各々が単一 BGP テーブルの作業
（best-path と advertise）をどう並列化するか**。3 つの異なる答え:

- **BIRD 3.3** はテーブル/プロトコルを *またいで* 並列化し、1 テーブル内では
  決してしない: 単一テーブルの best-path はテーブルごとの 1 つのロックの下で
  **直列**、読みはロックフリー（RCU キャッシュ）、egress はロックフリー
  ジャーナル（`lfjour`）経由で **コンシューマごとに並列**。
- **GoBGP** は 1 テーブルを共有メモリ上の **2048 個のバケット *ロック*** で
  prefix ハッシュによりシャード化する: best-path は prefix をまたいで並列に
  動くがロック内で、export *ポリシー* は producer 上で直列に動く
  （encode/write のみがピアごとに並列）。
- **zebra-rs** は prefix ハッシュで **所有された** シャード（shared-nothing、
  ホットパスロックなし）にシャード化する。BIRD も GoBGP も egress を
  ピアごとに並列化することが Phase E のクロスバリデーション。

メモは各々の完全なアーキテクチャ、図、比較表、検証済みのソースアンカー、
スタックごとの要点（ここで要約した枠組みへの訂正を含む）を持つ。

### 新規 Established ピアへの Loc-RIB の初期供給（同期パス）

2 つ目の先行事例の軸で、**セッション確立時のダンプ**（B.4 同期パス）に固有:
ピアが Established に達したとき、各スタックは Loc-RIB をどう歩いてその 1 つの
新規ピアに advertise するか。BIRD 3.3.0（`proto/bgp/`、`nest/rt-export.c`、
`sysdep/unix/io-loop.c`）と GoBGP `master`（`pkg/server/`、
`internal/pkg/table/`）に対して検証。

| 次元 | zebra-rs | BIRD 3.3.0 | GoBGP（master） |
|---|---|---|---|
| **トリガ** | FSM→Established → `route_sync()`（`peer.rs:1484`→`route.rs:9600`）が AFI/SAFI ごとに `route_sync_<af>` をディスパッチ | `proto_notify_state(PS_UP)` → channel `CS_UP` → `channel_start_export` → `rt_export_subscribe`（汎用 nest。旧 `bgp_feed_begin` は廃止） | ピアごとの FSM goroutine → `handleFSMMessage` ESTABLISHED → `getBestFromLocalCallback` → `sendfsmOutgoingMsg` |
| **Loc-RIB 読み** | 同期 **ワンショット** `Vec` collect（AddPath → cands `.0`、else best `.1`） | **再開可能カーソル**（`rt_export_get`、`feed_index`）、ステップごとに 1 net、ダンプ途中で yield | 同期 **ワンショット** `RLock` 下（`GetBestPathList` / `GetPathList`） |
| **スレッディング** | **単一 main タスク** — 全ピアのダンプ + 定常状態 ingest がここで直列化、ビルドは直列、v4 読みは `mirror_v4` 経由 | スレッドプール上の **プロトコルごとの birdloop**: ピアはコアをまたいで並列、1 ピアは直列、協調的な `MAYBE_DEFER_TASK` yield | 共有 `RLock` 下の **ピアごとの FSM goroutine**: ピアは並列、1 ピアは直列、エンコードは別の `sendMessageloop` goroutine 上 |
| **Adj-RIB-Out** | **常時 on** のピアごと `adj_out.<af>`、ダンプ中に埋める。withdraw ゲートがそれを読む | **オプトイン**（`export table` → `tx_keep` バケット/prefix ハッシュ）。デフォルトは送信後に prefix を解放、withdraw はジャーナルに乗る | **永続なし**: `sentPaths` マップ（dest→path-ids）。フル `AdjRib` はモニタリング / soft-out 用に一時的にのみ再構築 |
| **バッチ / 合体** | attr ごとのバケット → 属性集合ごとに 1 MP_REACH（`send_ipv4_direct`） | 属性バケット（`bgp_get_bucket`）を最大パケット長にパック（`bgp_create_update`） | 同一 attr の "cages" + メッセージ間合体 ≤2048（`CreateUpdateMsgFromPaths`） |
| **バックプレッシャ** | **上限なし** の *エンコード済みバイト* の `packet_tx` → ビルド側バックプレッシャなし。TCP は `packet_rx` をドレインする writer のみ | **TCP ソケット** が `bgp_fire_tx` を一時停止/再開 — メモリ上限あり、writable で再開 | **上限なし** の *パス* の `InfiniteChannel` → ビルド側バックプレッシャなし。TCP は `sendMessageloop` のみ |
| **End-of-RIB** | **常に**、ファミリごと（`send_eor_<af>`） | graceful-restart 下 **のみ**（`BFS_LOADING`→`LOADED`） | GR または RTC 下 **のみ**（`table.NewEOR` センチネル） |

**シャーディング作業への要点。**

- **ピア間並列性は当然の前提 — zebra-rs はそれを欠く外れ値。** BIRD
  （プロトコルごとの birdloop）と GoBGP（`RLock` 下のピアごと goroutine）は
  どちらも新規ピアのダンプをそのピア自身のコアで動かすので、他ピア *や*
  定常状態 ingest を決して head-of-line ブロックしない。zebra-rs はそのすべてを
  1 つの main タスクにファンネルする — B.4 / Phase E が狙う上限。ただし *軸* は
  異なる: 先行事例は *ピア間* 並列性を得る（各ピアは依然 1 ルートずつ）。A2 の
  `DumpV4`-to-shards 計画は *ピア内* 並列性（prefix をコアにシャード化）を
  狙い、これは **BIRD も GoBGP もやっていない**。両者は補完的 — zebra-rs は
  最終的に両方を欲しがり得る。
- **ワンショット collect は RR スケールのダンプには最悪のパターン。**
  zebra-rs と GoBGP はどちらもパスリスト全体を前もって materialize する。
  BIRD だけが再開可能で協調 yield するカーソルをストリームする。zebra-rs が
  最も露出しているのは、それが *キューイング前に main タスクでバイトにも
  エンコードする* ためで、ビルド全体に yield ポイントがない。BIRD の
  `feed_index` + `MAYBE_DEFER_TASK` が「ダンプ中に他の作業を飢えさせない」の
  参照設計で、フルシャーディングの前でも借りる価値がある。**構築済み** —
  Tier-1a 再開可能カーソル（`ZEBRA_BGP_SYNC_CHUNK`）が IPv4-unicast に対して
  まさにこれを行う（B.4「再開可能同期カーソル」セクション参照）。main ループの
  最大停止が 12–91× 低く、RIB サイズにフラットと計測。
- **zebra-rs は選択により最も重い Adj-RIB-Out を持つ。** 常時 on のピアごと
  `adj_out` はピアごとにメモリを要する（シャーディングのメモリ利得に対する
  実コスト項目）が、再導出なしの O(1) withdraw ゲートを買う。GoBGP は本質的に
  何も持たない（path-id 集合）。BIRD はオプトインノブでのみ。B.4 修正 —
  同期 *中* に `adj_out` を登録 — がそのゲートを正しく保つもの。他の 2 つは
  それを回避する（ジャーナル / `sentPaths`）。
- **バックプレッシャ: zebra-rs ≈ GoBGP（上限なし、ビルドは決してブロック
  しない）、BIRD が上限ありの外れ値。** 遅いピアは zebra-rs と GoBGP の両方で
  インメモリキューを成長させる。A2 がダンプをシャードにファンするとき、各
  シャードの送信にはバックプレッシャの仕組みが必要 — 遅いピア下で上限付き
  メモリが重要なら BIRD の resume-on-writable がコピーすべきモデル。
  **構築済み**（Tier 1b）A2 に先立って: リアルタイムのピアごと egress ゲージが
  watermark（`ZEBRA_BGP_SYNC_EGRESS_HIGH`）で同期カーソルを park する — BIRD の
  resume-on-writable を単一タスク同期に適用したもの。A2 のシャードごとの送信は
  同じゲージを再利用できる。
- **EoR**: zebra-rs はファミリごとに無条件で End-of-RIB を出す。他の 2 つは
  graceful-restart にゲートする。無害だが interop のために注意 — zebra-rs
  スピーカーは非 GR neighbor にも EoR を送る。

## 12. 改善ロードマップ（先行事例に基づく）

§11 の比較は zebra-rs を 3 つの中で唯一の shared-nothing 設計として位置づける
— これは Rust に適合し（所有権 > GC される共有ポインタ > ロックフリー RCU）、
最強の compute 並列 + egress 並列のストーリーを与える。3 つのアーキテクチャ
ギャップが優先順位順で残る。最初の 2 つは 3 スタックすべてが異なる箇所、
3 つ目は zebra が独自に制約されている箇所。

**P1 — E.2+ グループ親和性 update-worker、シャードごとのジャーナルで供給。**
今日、シャードの reduce は *out-policy 事前計算*（E.1/E.2）を並列化するが、
バケット化 / キャッシュ / エンコード / adj-out は依然 **main の reduce
スレッド上で直列** に動く。完全な Juniper 形態はグループごとの egress を、
静的な group→worker 親和性を持つ M 個の専用ワーカーに移し、シャードから直接
`AdvDelta`（RTO）を供給して main の reduce をバイパスする。BIRD 3.x が参照
土台: **シャードごとの append-only ジャーナル**（`lfjour` の形 — seq 番号 +
ワーカーごとのカーソル）により、各 update-worker は main がファンアウトする
代わりに自分のペースでデルタを *pull* できる。Adj-RIB-Out の統一（上記）が
イネーブラ — 今や全ファミリがワーカーが diff するピアごとの `adj_out` を持つ。
順序は依然成り立つ: 1 prefix → 1 シャード → 1 ワーカー。これは残る最高価値の
単一項目であり、§11 が明示的に指す項目。

**P2 — バックプレッシャ。** スレッド間チャネルは現在すべて上限なし（シャード
inbox `std::sync::mpsc`、tokio 結果チャネル、egress ハンドオフ）— GoBGP が
持つのと同じ弱点（`InfiniteChannel`）であり、BIRD が明確に先行する唯一の箇所
（`lfjour` トークン + slowest-consumer watermark GC がジャーナルを上限化する）。
遅いコンシューマ（ピア、FIB、RIB デーモン）がメモリを無制限に成長させ得る。
選択肢: `try_send` + オーバーフロー計上付きの上限付きチャネル、または — P1 が
ジャーナルを着地させるなら — BIRD の watermark/token モデルをそれに直接採用
（最も遅いカーソルへ GC）。ファンアウト/遅いピアのベンチ後に決める、前ではなく。

**P3 — 所有権の粒度をワーカースレッド数から切り離す。** 今日
`shard == OS thread` なので、シャード数は所有権の粒度 *かつ* 並列度を同時に
表す — まさにこれが knee が N=4（N=cores ではなく）である理由であり、シャードが
egress プールとコアを奪い合う理由（`max(1, cores − shards)` 分割）。他の 2 つの
スタックはこれらを分離する: GoBGP は `GOMAXPROCS` goroutine が供給する 2048 の
ロック/所有権ドメインを持つ。BIRD 3.x の `birdloop` バランサは多数のループを
固定スレッドプールに work-steal する。ここでの類比: 多数の *論理的* シャード
（細かく安定した prefix 所有権）を small fixed worker プールに work-stealing で
マップし、オペレータが N をコア数に対して手調整するのをやめさせる。より大きな
リファクタ。N 調整の摩擦が本番ワークロードで実在すると証明された場合のみ
価値がある。

**より低優先 / 既出。** プールディスパッチを v6/VPNv6/LU に拡張する（上記の
直近ギャップ）のは機械的でありアーキテクチャ的ではない。中央 RIB デーモンが
1:1 RIB-FIB ロールの次の直列ボトルネックになること（§10）は BGP 側の
シャーディングに関係なくエンドツーエンド利得を束縛する — 別の取り組み。
