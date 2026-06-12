# BFD / S-BFD / STAMP の XDP/eBPF オフロード検討メモ

> zebra-rs / zebra-agent 向け技術リファレンス
> 内容: Linux 上での BFD/Echo/S-BFD/STAMP のデータプレーンオフロード可能性、商用ルータの対応状況、ディスクリミネータ運用、実装方針
> 注: 各社の対応状況・既定値はリリース/プラットフォーム依存。実装前に最新ドキュメントで再確認すること。

---

## 0. 要点サマリ（先に結論）

- **純 XDP で BFD/Echo/S-BFD/STAMP を「丸ごと」実装した成熟プロジェクトは存在しない。** 最大の障害は **TX タイマー**（XDP は RX 起動のみで、自発的な周期送信ができない）。
- **role を分けると整理できる**:
  - **Reflector（折り返し側）= ステートレス → XDP の好適ユースケース**（`XDP_TX`）。
  - **Originator/Sender（送出・検知側）= TX タイマーとタイムアウト検知が必要 → `bpf_timer`（5.15+）かユーザ空間が必須**。RX 検証は XDP が得意。
- **S-BFD は SR-TE / SR Policy のパス継続性チェック用途が実態。** Initiator が能動、Reflector がステートレス。
- **SRv6 では各社でアプローチが割れる**:
  - **Cisco**: S-BFD は SR-MPLS/IPv4 専用。SRv6 liveness は **STAMP ベースの Performance Measurement (PM/IPM)**。
  - **Juniper**: SRv6 TE パスに **S-BFD 対応**（IPv6 ディスクリミネータ）。
  - **Nokia**: SRv6 Policy に **S-BFD 対応**。
- **zebra-rs 実装方針**: 制御プレーン（Rust / aya ユーザ空間）と データプレーン（aya-ebpf / XDP）を分離。Reflector を XDP に置き、Originator/Sender 側はタイマー部分をユーザ空間 or `bpf_timer`。フル機能（高精度・認証・SRv6 encap）が要る所は **AF_XDP** に寄せる。

---

## 1. Linux における BFD の eBPF/XDP 実装の現状

- 純 XDP/eBPF だけで完結する成熟した BFD 実装は無い。periodic TX（ms 単位の自発送信）を eBPF が起こせないのが根本問題。
- 既存の Linux BFD はすべてユーザ空間 or カーネルモジュール:
  - **FRRouting `bfdd`**: 事実上の標準。BGP/OSPF/IS-IS と連携。
  - **OpenBFDD / FreeBFD / aiobfd(Python)**: スタンドアロンのユーザ空間デーモン。
  - **kbfd**: 旧 Quagga/zebra 時代のカーネルモジュール（メンテ停止）。
- Cilium の BGP Control Plane への BFD 追加議論でも「純 eBPF 実装の最大の障害はタイマー送信」と明記されている。
- **XDP の現実的な使いどころ**: セッション状態と TX タイマーはユーザ空間（or `bpf_timer`）に置き、XDP は **RX 側の高速化**（BFD 制御パケットのパース・discriminator のマップ照合・detect-timer リセット・liveness 喪失の高速検知）に使う。

---

## 2. BFD Echo と XDP（reflector / originator の分離）

BFD Echo は本質的に「ローカルが送出 → リモートのフォワーディング面が折り返し → ローカルが戻りを見て判定」。

### Reflector 側 = 純 XDP で完全実装可能（最良ケース）
- UDP 3785 宛を受けたら、宛先/送信元 MAC を入れ替えて受信 IF へ `XDP_TX` で送り返すだけ。
- L2 折り返し（MAC スワップのみ）なら理屈上は IP/UDP チェックサム再計算も TTL デクリメントも不要。
  **【2026-06-01 訂正】** ただし実機相互接続では成り立たない。BFD Echo の折り返しは「リモートの
  **フォワーディング面**が返す」= 1 ホップであり、FRR の forwarding-plane Echo 受信
  (`bfd_recv_ipv4_fp`) は折り返しフレームの **TTL=254（255 から 1 減算）を必須**とし、それ以外は
  破棄する。したがって reflector は **TTL を 1 減算し IPv4 ヘッダチェックサムを再計算（RFC 1141:
  チェックサム += 0x0100 / 桁上げ畳み込み）する必要がある**（UDP チェックサムは TTL を含まないため
  不変）。zebra-rs の XDP reflector は実装済み・FRR `echo-mode` と相互接続検証済み。

  **[2026-06-07 update — FRR Echo addressing is asymmetric across IPv4/IPv6; the
  reflector must treat each differently. Found via a real-world IPv6 loop against
  FRR.]** Reading the FRR source, the Echo transmit dispatch
  (`ptm_bfd_echo_xmt_TO`, `bfdd/bfd.c:583-590`) hardcodes an `if IPv6 … else`
  split:
  - **IPv4 Echo** (`ptm_bfd_echo_fp_snd`) is **self-addressed**
    (`src == dst == local`, TTL 255) and looped by the peer's **forwarding
    plane** — the RFC 5881 model. The reflector never touches the dst (already
    the originator), so a **MAC swap + TTL decrement** suffices. This is the path
    already lab-validated against FRR `echo-mode` (see the 2026-06-01 note).
  - **IPv6 Echo** (`ptm_bfd_echo_snd`, `bfd_packet.c:326`) is **peer-addressed**
    (`src = local, dst = bfd->key.peer`, hlim 255) and looped by the peer's
    **bfdd in software** (`bp_bfd_echo_in`): an IPv6 link-local Echo cannot be
    forwarding-plane looped. FRR's reflect sends the frame back to the source at
    `hlim - 1` (= 254); the originator IDs its own return by `hlim != 255`
    (255 → re-reflect, otherwise → match by `my_discr`). That hlim distinction is
    what stops a mutual-reflection loop.
  - **Bug + fix:** the XDP reflector's IPv6 path must therefore swap the IPv6
    src/dst too, not just the MACs. Without it the reflected frame keeps
    `dst = us`, FRR's forwarding plane bounces it back, and it ping-pongs until
    hlim 0 (observed 2026-06-07 on IS-IS IPv6 BFD vs FRR: tcpdump shows src/dst
    unchanged, hlim decrementing, MAC flipping between the two boxes). Fix:
    `swap_ip6` in `try_reflect_v6` (16-byte ×2 volatile byte-swap, same shape as
    `swap_macs` to dodge the verifier's memcpy rejection). **No checksum fix-up**
    (the UDP pseudo-header sum `src + dst` is invariant under the swap). The hlim
    255→254 decrement stays mandatory (FRR reflects only hlim 255). A
    self-addressed Echo (e.g. our own originator) has `src == dst`, so the swap is
    a no-op and its return is still caught by the `OUR_LOCAL_IPS_V6` branch.
  - **IPv4 path left unchanged (minimal):** FRR IPv4 Echo is self-addressed, so
    `try_reflect_v4` (MAC swap + TTL decrement, no IP swap) is correct. The only
    way IPv4 Echo is peer-addressed is the non-Linux FRR branch
    (`#else → ptm_bfd_echo_snd`, dst = peer) or another implementation; the same
    swap would fix that harmlessly (the swap is commutative, so neither the IPv4
    header checksum nor the UDP pseudo-header checksum changes) but is unnecessary
    for Linux / RFC-compliant peers.

  **Cross-vendor / RFC check — is FRR's IPv6 model an industry convention? No,
  it's FRR-specific (and contrary to RFC 5881):**
  - **RFC 5881 §5**: Echo is **self-addressed** — the destination MUST be chosen
    so the remote *forwards* it back ("a system implementing the Echo function
    MUST be capable of sending packets to its own address … bypassing the normal
    forwarding lookup"), and the source SHOULD NOT be an IPv6 link-local address.
    FRR's IPv6 Echo violates all three (dst = peer, link-local src, software
    reflection).
  - **Cisco (IOS-XR)**: no IPv6 Echo at all — Echo is IPv4-only ("echo packets
    transmitted over UDP/IPv4, port 3785"); IPv6 liveness uses async BFD. Nothing
    to be consistent with.
  - **Juniper (Junos 22.4R1+)**: `echo` / `echo-lite`; `echo-lite` works "without
    requiring BFD configuration on the neighbor" = forwarding-plane (RFC
    self-addressed), the **opposite** of FRR's "peer must run a reflector".
  - **FRR's own docs**: "echo mode works only when the peer is also FRR" unless
    distributed BFD — confirming the IPv6 model is a both-ends-FRR feature.
  - **Implication**: the reflector's v4/v6 asymmetry intentionally mirrors FRR's.
    `swap_ip6` is robust to **both** addressing models — a no-op for
    self-addressed (RFC / Juniper echo-lite / our own originator) and a retarget
    for peer-addressed (FRR) — so making zebra-rs an FRR-compatible IPv6 reflector
    does not break standards-compliant peers. The old code/README premise "IPv6
    Echo is self-addressed, so no swap needed" held only for our own originator;
    FRR originators are peer-addressed.
- 「unaffiliated BFD echo」のリフレクタ概念に一致（BFD スタックを持たない機器の前段に小さな XDP リフレクタを置く構成が可能）。

### Originator 側 = XDP 単体では不可
- Echo の定期送出（TX）→ `bpf_timer` かユーザ空間。
- 折り返してきた Echo の受信・検証（RX）→ XDP が得意（マップに last-seen / seq を持って照合）。
- detect タイムアウト（戻ってこない → Down）→ タイマー起動が必要なので XDP 単体不可。

> **実装済み（as-built）**: reflector / originator とも実装済みで、ヘルパは
> **`xdp-bfd-echo`**（旧 `bfd-echo-reflector`）に統合。ここの予測どおり TX は
> ユーザ空間 `AF_PACKET`、detect は XDP が戻り Echo ごとに per-session
> `bpf_timer` を arm する方式（戻りが止まると `Down` + `EchoFunctionFailed`）。
> `bpf_timer`-from-XDP のカーネル検証はラボ確認待ち。

### 実装メモ
- Echo ペイロードは RFC 5880 §6.4 で **"a local matter"**（送出側裁量）。自分の discriminator + seq + 送出タイムスタンプを詰めておくと RX 側 XDP のマップ照合が安価。
- 性能は折り返しジッタが検知タイマーの攻め具合を左右 → reflector は native モード（i40e/ice/ixgbe/mlx5 等）が望ましい。

---

## 2b. 標準 BFD 制御パケットの expiration 監視オフロード（2026-06-12 実装）

§1 末尾の「XDP の現実的な使いどころ = RX 側の detect-timer リセット・liveness
喪失の高速検知」をそのまま実装したもの。Echo originator の `bpf_timer` 検知
（§2）と同じ機構を、**UDP/3784 の標準 BFD 制御パケット**に適用する。

- **XDP 側は純粋な観測者**: 制御パケットを TTL/HopLimit==255（GTSM, RFC 5881
  §5）・version==1 だけ確認し、Your Discriminator で `CONTROL_TIMERS`
  (BTF map, 値は Echo と共通の `DetectState`) を引いて `bpf_timer` を再アーム、
  フレームは**必ず `XDP_PASS`**。FSM・Poll/Final・パラメータ再交渉はすべて
  従来どおりデーモンが処理する（liveness タイミングだけがカーネルに移る）。
  Echo reflector と違いパケット書き換えが無いので、検証器対策も不要だった。
- **確立後のみアーム**: 確立前はリモートが `Your Discriminator = 0` を送るため
  マップのキーにできない。zebra-rs は Up 遷移で `detect-add <discr>
  <detect-us>`、Up を離れたら `detect-del` をヘルパー stdin に送る
  （`Bfd::detect_offload_reconcile`、Echo の reconcile と同形）。再交渉で
  detection time が変わったら `detect-add` を再送（マップ要素の置換 =
  旧タイマーはカーネルが cancel）。
- **userspace タイマーはバックストップに格下げ**: ウォッチドッグがアーム中は
  4 倍（`DETECT_BACKSTOP_FACTOR`）に伸ばして保持。ヘルパー死亡
  （`Message::HelperGone`）で即 1 倍に戻す。偽 Down（デーモンが
  スケジュールアウトしてソケットキューに溜まったのに userspace タイマーが
  先に発火）と検知遅延の両方を排除でき、attack 的な短い検知時間
  （sub-10ms 級）を正直に張れるようになる。
- **送信側はオフロードしない**: 自分の制御パケット送信はデーモンのまま。
  デーモンが完全に停止すれば相手側の検知で落ちる（こちらの RX 検知だけが
  カーネル化される）。
- **スコープ**: single-hop のみ（ヘルパーは per-ifindex アタッチ。multihop は
  入口 IF が固定でなく GTSM 床も 255 未満）。認証付きセッションは将来 BFD
  auth が入った場合オフロード禁止にすること（XDP では MD5/SHA1 を検証
  できない）。
- **設定**: OSPF / IS-IS / BGP の `bfd { detect-offload true; }`
  （per-interface または per-neighbor / instance-level、echo-mode と同じ
  継承）。BGP は single-hop のみ（multihop では inert）。
- **BGP の ifindex 解決（フォローアップ PR で追加）**: BGP の BFD
  SessionKey は従来 `ifindex: 0` 固定 — per-ifindex アタッチのヘルパーが
  **一度も起動できず**、BGP echo は実質 inert だった。`ConnectedSubnets` に
  記録元 ifindex を持たせ（`ifindex_for`、v6 link-local は除外）、single-hop
  セッションを connected interface でキーする。アドレス学習が `bfd enable`
  より後なら `RibRx::AddrAdd` フックの `bfd_reconcile_all` が再キー
  （unsubscribe→subscribe）。これで BGP の echo / detect-offload 両方が
  実際に機能する。
- **検証**: `scripts/veth-detect-test.sh` — 600ms 検知で 150ms 間隔の制御
  パケットを 1.2 秒流し（早発 = bootstrap fallback 発火で FAIL、つまり XDP
  再アームの実証）、停止後 ~600ms で `detect-down` が来るのを確認。
  2026-06-12 ラボ PASS。

---

## 3. S-BFD (Seamless BFD) 概要

- **RFC 7880 (2016)。** classic BFD のハンドシェイク（Down→Init→Up の三方向）を排除した派生。
- **事前配布された 32bit ディスクリミネータ**を使う。Initiator は対向の reflector discriminator を既知なので、ネゴ抜きで即パケット送出 → 即反射で到達性確認（1 往復で完結）。
- **非対称な 2 役割**:
  - **Initiator**: 能動。状態機械を持ち送出・判定。
  - **Reflector**: ステートレス。自分の discriminator 宛パケットを受けたら my/your discriminator を入れ替えて返すだけ。
- **ポート**: UDP 7784（S-BFD 制御） / 7785（S-BFD Echo）。※ classic は 3784/3785。
- **用途**: オンデマンド到達性確認、**SR-TE / SR Policy のパス検証**（特定のセグメントリストに沿って流して反射を見る）。
- **XDP 向きな理由**: reflector がステートレス（UDP 7784 一致 → your discriminator をマップ照合 → my/your 入替＋state 設定 → MAC/IP 入替 → UDP チェックサム増分更新 → `XDP_TX`）。discriminator 書換とチェックサム修正の分だけ classic echo の MAC スワップより一手間多い。
- **関連 RFC**: 7880(コア) / 7881(IPv4/IPv6/MPLS カプセル化) / 7882(ユースケース) / 7883(IS-IS でのディスクリミネータ広告) / 7884(OSPF 拡張)。

---

## 4. 商用ルータの S-BFD 対応状況（SR-TE / SR Policy 文脈）

> 4 社とも対応。実態は「SR-TE/SR Policy のヘッドエンドが initiator、テールが stateless reflector」。汎用リンク BFD（OSPF/IS-IS/BGP ネイバー監視）は classic BFD のまま、という住み分けが共通。

| ベンダー | 対応 | 主な制約・メモ |
|---|---|---|
| **Cisco IOS-XE (ASR1000)** | ○ | SR-TE で S-BFD。**IPv4 のみ / シングルホップのみ**。テールが reflector |
| **Cisco IOS-XR (NCS5500)** | ✗ | **Seamless BFD 非対応** と明記。機種差が大きい（要個別確認） |
| **Cisco IOS-XR (ASR9000 等)** | ○ | SR-TE で sBFD reflector/initiator 設定あり |
| **Juniper (Junos / Evolved)** | ◎ | colored/non-colored SR LSP、SR policy。23.2R1〜 S-BFD FRR（MX）。Evolved 22.4R1〜 PTX で remote discriminator 自動導出 |
| **Nokia (SR-OS)** | ◎ | SR-TE LSP は 19.10.R1〜。**CPM-NP 必須、最小 10ms**。static/BGP SR policy 対応 |
| **Arista (EOS)** | ○ | EOS 4.24.1F〜（SR-TE/SR Policy）。新しめのリリースで **S-BFD Hold-down Timer**（4.34/4.35/4.36F） |

---

## 5. SRv6 に絞った対応（Cisco / Juniper / Nokia）と End.X 監視

### Cisco（IOS-XR）: SRv6 では S-BFD を使わない
- S-BFD は **SR-MPLS / IPv4 専用**（制御パケットは順逆ともラベルスイッチ）。
- SRv6 liveness は **Performance Measurement (PM) の liveness detection = STAMP (RFC 8762/8972) ベース**。
  - MPLS 以外の IPv4/IPv6/SRv6 に共通適用。**loopback measurement-mode**（ヘッドエンドが宛先を自分のループバックに設定、SR ポリシーと同じカプセルで注入）。
  - SRv6 では **SRH 内フローラベル(20bit)** で ECMP パスごとの活性を監視。
  - 商用名 **Integrated Performance Measurement (IPM)**。STAMP 準拠、uSID ポリシー統合。
- 背景: S-BFD(接続性) と STAMP(性能) の併用は複雑/高コスト → 統合提案 `draft-gandhi-spring-sr-enhanced-plm`。

### Juniper（Junos / Evolved）: SRv6 でも S-BFD 可
- SRv6 TE パスに S-BFD 対応:
  - ingress: `[edit protocols bfd] sbfd local-discriminator`、SRv6 TE パス側 `bfd-liveness-detection` 配下に `sbfd remote-discriminator`。
  - egress(responder): `sbfd local-discriminator <n> local-ipv6-address <addr>`。responder の local = ingress の remote と一致必須。
  - IPv6 ローカルホストアドレス限定の responder 向けに `bfd-liveness-detection sbfd destination-ipv6-local-host`。
- STAMP/TWAMP/RPM も別途あり（性能測定）。

### Nokia（SR-OS）: SRv6 Policy に S-BFD
- SRv6 Policy への Seamless BFD で「silent」やデータパス障害を高速検知。
- アクティブポリシーのセグメントリストで S-BFD ダウン → フェイルオーバー。全 S-BFD ダウン → SRv6 最短パスへフォールバック。

### 参考: Huawei / H3C
- SRv6 TE policy に S-BFD（静的セッションのみ、remote discriminator 手動必須）。

### End.X（隣接 SID）監視について（重要）
- 上記 S-BFD/PM はいずれも **エンドツーエンドのセグメントリスト（SR ポリシー）単位**の監視。「特定 End.X SID だけを専用セッションで」という機能ではない。
- 個々の End.X（uSID 表記では uA SID）の死活は **IGP(IS-IS) 隣接状態に従属**:
  - リンク/隣接ダウン → IGP が End.X SID を withdraw → 保護付きなら TI-LFA バックアップへ。
- したがって **End.X 単位の高速検知 = リンクの classic BFD ＋ IGP withdraw ＋ TI-LFA**、End.X を含む特定パスの到達性 = S-BFD/PM で端から端まで監視、という二層構成。
- SRv6 で BFD/S-BFD の**返り経路を決定的にしたい**場合、SRH に順方向＋逆方向の SID リストを両方入れて返りパスを固定する手法あり（特定 End.X 経由パスのピンポイント監視に有効）。

---

## 6. ディスクリミネータの取得方法（各社）

> 取得方法は大きく 3 系統: 手動設定 / IP アドレス由来 / IGP 広告による自動配布。

### 標準（自動配布の土台）
- 32bit 値、管理ドメイン内で一意（RFC 7880）。
- **RFC 7883**: IS-IS の Router CAPABILITY TLV で広告。
- **RFC 7884**: OSPF の Router Information (RI) TLV（**Type 11**）で広告（OSPFv2/v3）。情報変更は SPF を起こさない。
- 上記を **BGP-LS** でコントローラへエクスポート可能。

### ベンダー別
| ベンダー | 手動 | IP 由来 | IGP 広告(7883/7884) | メモ |
|---|---|---|---|---|
| **Cisco IOS-XR** | ○ | ○ | （明示確認できず） | reflector: `local-discriminator {ipv4-address \| 32bit \| dynamic \| interface}`。initiator: **RTI テーブル**で宛先→remote discriminator マッピング（`remote-target ipv4 <addr>`）。IPv4 宛なら宛先アドレスをそのまま remote discriminator に使える。XRv9k は S-BFD 非対応 |
| **Juniper** | ○ | ○ | - | Evolved 22.4R1〜 `set protocols bfd sbfd local-discriminator-ip` でトンネルエンドポイントから remote 自動導出、共通 sBFD テンプレート |
| **Nokia SR-OS** | ○ | - | **○（最も自動化）** | 7883/7884 で IGP リンクステートに opaque 情報としてエンコード → BGP-LS でエクスポート |
| **Huawei/H3C** | ○（必須） | ○(整数変換) | - | SRv6 でも静的のみ、remote discriminator 手動必須 |

---

## 7. Classic BFD Echo の片方向運用

- **可能。Echo は本質的にシステム単位で独立した非対称機能。** 片側(A)だけが Echo を運用し、対向(B)は折り返しに徹する、が自然な形。
- A の Echo は A→B→A と往復するので物理両方向を試験するが、**死活が分かるのは A だけ**。B も欲しければ B が独立に B→A→B を回す（= 2 本の独立した片方向 Echo）。
- **ネゴシエーション上の注意 `Required Min Echo RX Interval`**:
  - 「自分が Echo 受信(折り返し処理)をどの最小間隔まで支えられるか」を相手に伝える値。
  - **0 = Echo 受信非対応** → 相手は Echo を送ってはいけない。
  - 片方向 Echo 成立条件: A は Echo 有効化、B は自分の Echo は不要だが **Echo 受信サポート（非ゼロ）を広告**する必要あり。
- **前提**: classic Echo は単独セッションではなく、**先に非同期制御セッションが Up している前提**の補助機能。Echo 活性時は制御パケットレートを下げてよい。
- **単一ホップ専用**（RFC 5881）。マルチホップ BFD（RFC 5883）に Echo は無い。
- → この非対称性が「originator / reflector」分離そのもの。B(折り返し) = XDP_TX 折り返しに乗る側。

---

## 8. FRR の BFD Echo 既定値と「分散BFD」

### FRR の Echo 既定
- **`echo-mode`（Echo 送信）= デフォルト off（無効）。**
- `echo receive-interval`（対向 Echo の折り返し受け入れ能力）= **デフォルト 50ms（非ゼロ）**。
  - → FRR は既定で「自分から Echo は起こさないが、相手の Echo は折り返す」reflector 的状態。
- `show bfd peers` の既定表示は `Echo transmission interval: disabled`。
- **FRR 固有の注意**: 分散 BFD でない限り、**Echo は対向も FRR のときだけ機能**（FRR が折り返しをソフトウェアで処理する実装都合）。商用ルータ相手に FRR Echo を当てにしない。
- 対比: 古い classic Cisco IOS は **Echo デフォルト on**。既定の向きはベンダーで割れるので相互接続時は両端確認。

### 分散 BFD（distributed BFD）とは
2 つの意味:
1. **一般的意味**: BFD セッションの周期送受信と検知タイマーを **ラインカード/データプレーン（ASIC/NPU）にオフロード**。RP は生成/削除と状態通知のみ。→ スケール、サブ 10ms タイマー、RP 切替/GR 中も BFD 維持。
2. **FRR の意味**: 制御プレーン(`bfdd`) と データプレーンを分離。**独自の BFD Data Plane Protocol (`bfddp`)**（`bfdd/bfddp_packet.h`）で外部データプレーン（HW/SmartNIC/別ソフトフォワーダ/ASIC）と session 設定・状態を交換。制御は FRR、足回りは外部、という分担。
- → zebra-rs 設計に直結: Rust 制御ロジック + XDP/eBPF データプレーン = まさに bfddp 分離の XDP 実装。Echo/S-BFD reflector の XDP オフロードはその「データプレーン側」。

---

## 9. TWAMP Light / STAMP の XDP オフロード実現性

> STAMP = Simple Two-way Active Measurement Protocol (RFC 8762/8972)。TWAMP Light と合わせて制御チャネル省略 + Sender/Reflector の 2 役。

### 結論
- **liveness だけが目的**なら Reflector は純 XDP で十分実現可能（BFD echo reflector に近い）。
- **正確な遅延/ロス測定**まで狙うと XDP 単体ではタイムスタンプ精度で頭打ち → HW タイムスタンプ統合か AF_XDP へ。

### Reflector 側（BFD echo より一段重い）
- やること: 受信時刻 T2 取得、Sender の Seq/Timestamp/Error Estimate を「Sender〜」フィールドへコピー、Reflector の Seq(stateless=Sender seq / stateful=マップ) と TX 時刻 T3 埋め込み、src/dst IP・port・MAC 入替、IP/UDP チェックサム増分修正、`XDP_TX`。
- **XDP 有利な点**: Sender パケットはパディング(MBZ)を持ち、Reflector の追加フィールドがその中に収まる設計 → **パケット長を変えず in-place 上書き可**（`bpf_xdp_adjust_tail` 不要）。固定レイアウトで bounds check も素直。
- **難所**:
  - **タイムスタンプ精度**: RX は XDP がドライバ直後なので良好、対応ドライバなら `bpf_xdp_metadata_rx_timestamp` で HW RX 時刻。TX は `XDP_TX` で実送出前に T3 を書くため原理的誤差。HW TX タイムスタンプの反映は実用上困難。
  - **クロックドメイン**: STAMP は NTP/PTP 形式。`bpf_ktime_get_ns` は単調時計。PHC 同期環境では HW タイムスタンプ側が正確。純 XDP は SW 時計ベース → Error Estimate で不確かさを大きめ申告。
  - **認証(HMAC-SHA256)**: XDP データパスで非現実的 → **authenticated は XDP 不可、unauth のみ**。
  - **TLV(RFC 8972)**: 可変長 TLV ループは verifier 制約と相性悪。Direct Measurement(統計読出)等は XDP で扱いにくい。ベース(TLV なし)はトリビアル。
  - **SRv6 encap**: IPv6+SRH+UDP+STAMP のパース、返り経路で逆 SR Policy を積むなら `bpf_xdp_adjust_head` で SRH push（重い）。loopback モードなら通常 SRv6 フォワーディングに任せられて軽い。

### Sender 側（BFD originator と同じ）
- 周期送信 → `bpf_timer` / ユーザ空間。RX 検証と detect-timer リセットは XDP 可。遅延/ロス計算が要るならユーザ空間へ punt。

### 用途別実現性
| 用途 | 純 XDP | 備考 |
|---|---|---|
| liveness のみ (unauth, TLV なし, IPv4/単一ホップ IPv6) | ◎ | BFD echo reflector 並み。SW 時計で十分 |
| 粗い遅延/ロス測定 | ○ | HW RX タイムスタンプ推奨、TX 精度は割り切り |
| 高精度遅延(PTP 級) | △ | HW タイムスタンプ必須、TX 側に原理的誤差 |
| authenticated / TLV リッチ / 逆 SRH encap | ✗ | AF_XDP / ハイブリッドへ |

### 現実解: AF_XDP ハイブリッド
- XDP で対象 UDP（STAMP 既定 UDP 862）だけ AF_XDP(XSK) へ redirect → ユーザ空間高速パスで書換・タイムスタンプ(PHC)・HMAC/TLV/逆 SRH encap。性能と機能の両立。

### 環境注意
- Parallels on Apple Silicon の仮想 NIC は HW タイムスタンプも native XDP metadata も期待不可 → ラボは SW 時計＋generic/native XDP 止まり前提。精度評価は実機 NIC(mlx5 等)。

---

## 10. aya（Rust eBPF ライブラリ）

- Rust で eBPF を書くためのライブラリ/フレームワーク。**libbpf/bcc 非依存、純 Rust、syscall は libc crate のみ。**
- **2 crate 構成**: ユーザ空間 `aya`（ロード/マップ管理/アタッチ/イベント受信）+ カーネル空間 `aya-ebpf`（旧 aya-bpf、eBPF プログラム本体）。両者でデータ構造を共有可。
- **利点**: C ツールチェーン/カーネルヘッダ/カーネルビルド不要、ビルド高速。**BTF → CO-RE**（再コンパイル不要で別カーネルで動く）。musl リンクで単一自己完結バイナリ。ユーザ空間は tokio/async-std で async 対応。
- 対応: XDP / TC / kprobe / tracepoint / cgroup_skb、hash map / array / ring buffer 等。
- ドキュメント: aya-rs.dev（Aya Book）。
- → 「ユーザ空間(aya)=制御プレーン、カーネル(aya-ebpf)=データプレーン」が分散 BFD の control/data 分離と対応。zebra-agent(nftables→eBPF) の延長で reflector データパスを追加していく形。

---

## 11. zebra-rs 実装に向けたまとめ・次アクション

### アーキテクチャ方針
- **制御プレーン**: zebra-rs / Rust（セッション管理、IGP/BGP クライアント通知、discriminator マッピングテーブル）。
- **データプレーン**: aya-ebpf / XDP（reflector の折り返し、RX 検証、detect-timer リセット）。
- **TX タイマー / タイムアウト検知**: `bpf_timer`(5.15+) かユーザ空間。
- **フル機能（高精度測定・認証・SRv6 逆 encap）**: AF_XDP に redirect。

### 相互接続の整合ポイント（discriminator）
- reflector の local discriminator を **IPv6 ループバック由来**で持つ → Cisco/Juniper/Huawei と噛む。
- initiator 側で **エンドポイント IP → remote discriminator マッピング表**（Cisco の RTI 相当）。
- Nokia 流の完全自動運用に合わせるなら、**IS-IS 実装に RFC 7883 の S-BFD Discriminator sub-TLV** 送受信を追加 → BGP-LS に載せる（zebra-rs は IS-IS/BGP-LS 既にあるので自然な拡張）。

### SRv6 相手別の必要実装
- **Nokia / Juniper 相手**: SRv6 上の **S-BFD**（reflector/initiator、IPv6 discriminator）。
- **Cisco（IOS-XR）相手の SRv6**: 先方は S-BFD を話さず **STAMP ベース PM liveness** → zebra-rs 側も **STAMP (RFC 8762/8972, TWAMP-light) responder/sender** が必要。
  - → Nokia/Juniper 向けは S-BFD reflector の XDP オフロード、Cisco SRv6 向けは STAMP reflector を検討。

### 段階的実装案（XDP/aya）
1. **第 1 段**: unauth STAMP（or S-BFD）liveness reflector を純 XDP（in-place 書換＋`XDP_TX`）。Cisco SRv6 の loopback liveness / Nokia/Juniper の S-BFD に当てる。
2. **第 2 段**: 精度/機能が要る所だけ AF_XDP へ redirect。
3. 並行して originator/sender 側の TX タイマー（`bpf_timer` or ユーザ空間）と detect タイムアウト。

### 未着手 / 深掘り候補
- IS-IS RFC 7883 の Router CAPABILITY TLV 内 S-BFD Discriminator sub-TLV のエンコード仕様。
- unauth STAMP reflector の XDP パケット書換骨子（フィールドオフセット、チェックサム増分、aya/Rust ローダ）。
- SRv6 loopback モードでの返り経路設計。
- FRR `bfddp` メッセージ仕様（互換にするか独自データプレーンプロトコルにするか）。

---

## 参考リンク（一次情報優先）

### RFC / IETF
- RFC 5880 BFD / RFC 5881 BFD for IPv4/IPv6 single-hop / RFC 5883 Multihop BFD
- RFC 7880 Seamless BFD: https://datatracker.ietf.org/doc/html/rfc7880
- RFC 7881 S-BFD for IPv4/IPv6/MPLS
- RFC 7883 S-BFD Discriminators in IS-IS: https://www.rfc-editor.org/rfc/rfc7883.html
- RFC 7884 S-BFD Discriminators in OSPF: https://www.rfc-editor.org/rfc/rfc7884.html
- RFC 8762 STAMP / RFC 8972 STAMP Optional Extensions / RFC 8986 SRv6 Network Programming
- draft-gandhi-spring-sr-enhanced-plm: https://datatracker.ietf.org/doc/html/draft-gandhi-spring-sr-enhanced-plm

### ベンダードキュメント
- Cisco IOS-XE S-BFD with SR: https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/seg_routing/configuration/xe-17/segrt-xe-17-book/m_sr-smlsbfd-sspf.html
- Cisco SRv6 Performance Measurement: https://www.cisco.com/c/en/us/td/docs/iosxr/cisco8000/srv6/b-srv6-configuration-guide/m-performance-measurement.html
- Cisco IOS-XR BFD Commands (discriminator): https://www.cisco.com/c/en/us/td/docs/iosxr/ncs5500/routing/b-ncs5500-routing-cli-reference/b-ncs5500-routing-cli-reference_chapter_0111.html
- Juniper Segment Routing LSP (S-BFD over SRv6 TE): https://www.juniper.net/documentation/us/en/software/junos/mpls/topics/topic-map/segment-routing-lsp-configuration.html
- Juniper BFD overview: https://www.juniper.net/documentation/us/en/software/junos/high-availability/topics/topic-map/bfd.html
- Nokia Seamless BFD for SR-TE LSPs: https://documentation.nokia.com/acg/23-7-2/books/classic-cli-part-i/c212-s-bfd.html
- Nokia Automated S-BFD discriminator distribution: https://infocenter.nokia.com/public/7750SR225R1A/topic/com.nokia.OAM_Guide/automated_s-bfd-ai9exgsvaa.html
- Arista EOS BFD/S-BFD: https://www.arista.com/en/um-eos/eos-bidirectional-forwarding-detection

### FRR / eBPF / aya
- FRR BFD (echo-mode 既定, distributed BFD): https://docs.frrouting.org/en/latest/bfd.html
- FRR bfd.rst (bfddp): https://github.com/FRRouting/frr/blob/master/doc/user/bfd.rst
- aya: https://github.com/aya-rs/aya / https://aya-rs.dev/ / https://docs.rs/aya
- Cilium BFD 議論: https://github.com/cilium/cilium/issues/22394
