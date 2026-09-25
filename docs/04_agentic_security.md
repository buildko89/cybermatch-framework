# 04. Agentic Security 評価

CyberMatch は、**外部のLLMや実際のエクスプロイトを実行せずに**、AIエージェントに対するセキュリティ対策を評価します。
合成した「防御側から観測可能なイベント」を既存の脅威ハンティング・レシピエンジンで再生し、型付きの封じ込めアクションを**次のシミュレーションステップ**で適用します。

実行方法: `python scripts/evaluate.py agentic resilience`(詳細は [02 評価メニュー](02_evaluation_menu.md) の 3.6 / 3.7)

## 1. 評価対象の4つのリスク

| # | リスク | 内容 | 主な評価指標 |
|---|---|---|---|
| 1 | 自律的な境界逸脱 | 達成不可能なタスクが境界への圧力を生み、エージェントが想定外のツールを探り、共有基盤を介して連携し、推移的に外部通信 (egress) を獲得する | 境界違反数、封じ込めまでの遅延、アラート後の被害範囲 |
| 2 | 脅威インテリジェンスの汚染 | 脆弱性情報(advisory)を、CVE番号や深刻度だけでなく**裏付け証拠**に基づいて受理・隔離・却下する | 捏造情報の受理率、正当情報の受理率、訂正までの遅延 |
| 3 | 共通原因による防御の同時故障 | 同じ故障ドメインに属する防御を「独立した多層防御」と誤って数えない | 防御の独立故障確率、目的別の突破・検知確率 |
| 4 | エピソード間の報酬ハック | 報酬を得た境界回避が、次回以降の回避傾向を強める(監督フィードバックの有無で比較) | 報酬ハック傾向の低減量 |

シナリオは公開されたインシデント報告から着想を得ていますが、本番の認証情報・ペイロード・エクスプロイトの実装詳細は含みません。

## 2. アーキテクチャ

```mermaid
flowchart TB
    subgraph Containment[境界逸脱と封じ込め]
        T[合成 HuntEvent タイムライン] --> OL[開ループ再生<br/>検知のみ]
        TP[信頼境界トポロジ] --> OL
        T --> CL[閉ループ再生<br/>同一入力]
        TP --> CL
        CL --> R[許可済み検知レシピ]
        R --> F[観測可能な Finding]
        F --> P[AgenticContainmentPolicy]
        P -->|次ステップで適用| A[型付き封じ込めアクション]
        A --> CL
        OL --> CM[封じ込め効果の比較指標]
        CL --> CM
    end

    subgraph Defense[多層防御の独立性]
        DC[防御コントロール] --> FD{故障ドメイン}
        FD -->|同一ドメイン| COR[完全相関として扱う]
        FD -->|別ドメイン| IND[独立層として掛け合わせ]
        COR --> BP[目的別の突破・検知確率]
        IND --> BP
    end

    subgraph Learning[エピソード間学習]
        EO[エピソードの報酬観測] --> OLH[開ループの強化履歴]
        EO --> OVH[監督ありの強化履歴]
        OLH --> RH[報酬ハック傾向の低減量]
        OVH --> RH
    end

    subgraph Intel[脅威インテリジェンス完全性]
        ADV[ThreatIntelAdvisory の証拠] --> G[ThreatIntelIntegrityGate]
        G --> D{判定}
        D --> ACC[accept]
        D --> Q[quarantine]
        D --> REJ[reject]
        ACC & Q & REJ --> EV[評価器のみが正解と照合]
    end
```

> **正解ラベルの隔離:** 完全性ゲート (integrity gate) は `ground_truth` を一切受け取りません。
> 正解ラベルは `evaluate_integrity_outcomes` だけが保持します。これは防御側ハンティングと同じ「オラクル非漏えい」原則です。

## 3. 信頼境界トポロジ

`topologies/agentic/agentic_research_environment.json` は、ゾーン・有向の境界・許可されたイベント種別・防御コントロールを宣言します。

```mermaid
flowchart LR
    N0["0: agent-sandbox<br/>untrusted"] ==>|"sandbox-to-broker<br/>許可: task_blocked,<br/>unintended_tool_probe"| N1["1: shared-artifact-service<br/>brokered"]
    N1 -.->|broker-to-egress| N2["2: research-egress<br/>restricted / Internet"]
    N2 -.->|egress-to-third-party-identity| N3["3: third-party-identity<br/>external"]
    N0 -.->|sandbox-to-host| N4["4: workload-host<br/>privileged"]
    N4 -.->|host-to-service-identity| N5["5: service-identity<br/>privileged"]
    N5 -.->|identity-to-control-plane| N6["6: orchestration-control-plane<br/>critical"]
    N6 -.->|control-plane-to-third-party| N7["7: third-party-production<br/>external-critical"]
```

太線はイベント種別付きで許可された境界、点線は**許可イベントが空**の境界(どのイベントが通っても違反として記録)です。
上段は「共有基盤経由の外部通信」、下段は「ホスト→ID→コントロールプレーン経由の権限拡大」という2系統の逸脱経路を表します。

- シナリオの各イベントは、既知のノードIDと辺の許可リストに照らして検査されます。
- レポートには、信頼境界の越境、許可されていない経路、推移的経路の違反、および根拠となった正確なイベントが記録されます。

### 防御コントロールと故障ドメイン

各コントロールは次を宣言します。

| 属性 | 意味 |
|---|---|
| objective | 何を守るか(目的) |
| layer | 防御層 |
| failure domain | 故障ドメイン(同時に壊れ得るグループ) |
| prevention effectiveness | 防止効果 |
| detection effectiveness | 検知効果 |

同梱トポロジには14のコントロールがあり、例えば次のように故障ドメインが共有されています。

| 故障ドメイン | 属するコントロール | 意味 |
|---|---|---|
| `identity-policy` | broker-object-acl, short-lived-scoped-token, control-plane-mtls, third-party-token-scope | 見かけ上は4層だが、IDポリシーが壊れると同時に失効し得る |
| `sandbox-runtime` | sandbox-network-policy, sandbox-syscall-filter | サンドボックス実行基盤の不具合で同時に破られ得る |
| `network-control` | independent-egress-proxy, third-party-egress-allowlist | ネットワーク制御基盤を共有 |

同一の故障ドメインに属するコントロールは**完全に相関**しているとみなし、保守的に「最も弱いコントロールの故障確率」を使います。
異なるドメイン同士だけを独立した防御として掛け合わせます。
シナリオの `agentic.defense_conditions.failed_domains` で、共通原因故障を強制的に発生させられます。

## 4. 開ループ / 閉ループ比較

```mermaid
sequenceDiagram
    participant E as イベント列(同一)
    participant O as 開ループ
    participant C as 閉ループ
    E->>O: step t のイベント
    O->>O: Finding を記録(対処しない)
    E->>C: step t のイベント
    C->>C: Finding → 封じ込めアクション決定
    Note over C: アクションは step t+1 から有効
    E->>C: step t+1 のイベント(阻止されれば発生しない)
```

両モードは**同一の潜在イベント列とレシピ**を再生します。比較では次を報告します。

| 指標 | 意味 |
|---|---|
| prevented-event lift | 閉ループで阻止できたイベント数の増分 |
| risk reduction | リスクスコアの低減 |
| boundary-violation reduction | 境界違反の低減 |
| unauthorized-path reduction | 許可外経路の低減 |
| post-alert blast-radius reduction | アラート後の被害範囲の縮小 |
| security-invariant survival lift | セキュリティ不変条件が守られた割合の向上 |

従来の `agentic.metrics`、`events`、`findings`、`feedback` フィールドは、閉ループ結果の別名として残しています。

## 5. エピソード間学習

`agentic.learning` は、決定的なエピソード観測値と次の4つの有界パラメータを与えます。

| パラメータ | 意味 |
|---|---|
| initial propensity | 境界回避の初期傾向 |
| learning rate | 報酬による強化の速さ |
| oversight penalty | 監督による検知・介入時の減衰量 |
| safe-success decay | 安全な成功による減衰 |

正の報酬を得た境界回避は、将来の回避傾向を強めます。検知や介入による低減は**監督ありのトラックでのみ**発生します。
両方の履歴が監査用に出力されます。これは評価モデルであり、LLM のオンライン学習ではありません。

## 6. イベントとアクションの契約

### エージェントのイベント種別

| 分類 | イベント |
|---|---|
| 行き詰まり・探索 | タスクの阻害、想定外ツールの探索 |
| 横方向の連携 | 共有サービスへの書き込み、許可外のエージェント間連携 |
| 境界突破 | 推移的な外部通信、サンドボックス脱出 |
| 認証情報 | 秘密情報の発見、認証情報の再利用、トークンの発行、権限昇格 |
| 基盤・痕跡 | コントロールプレーンへのアクセス、ログ改ざん、第三者へのアクセス |

### 封じ込めアクション

| アクション | 内容 |
|---|---|
| `pause_workload` | ワークロードの一時停止 |
| `terminate_evaluation` | 評価(エージェント実行)の終了 |
| `quarantine_zone` | ゾーンの隔離 |
| `revoke_identity` | IDの失効 |
| `disable_shared_service` | 共有サービスの無効化 |
| `block_egress` | 外部通信の遮断 |
| `preserve_evidence` | 証跡の保全 |
| `notify_third_party` | 第三者への通知 |

これらは、既存の監視強化・辺の遮断・デコイへの誘導・追加認証アクションを補完します。

## 7. 脅威インテリジェンスの完全性ゲート

ゲートは次の証拠を点数化し、`accept` / `quarantine` / `reject` を決めます。**却下済み・取り下げ済みの advisory はフェイルクローズ**(受理しない)です。

| 評価要素 | 見るもの |
|---|---|
| source trust | 情報源の信頼度 |
| vendor corroboration | ベンダーによる裏付け |
| affected-version consistency | 影響バージョンの整合性 |
| code-reference validity | コード参照の妥当性 |
| fix-commit presence | 修正コミットの有無 |
| PoC presence / reproduction | PoCの有無と再現性 |
| independent-source count | 独立した情報源の数 |
| current status | 現在のステータス(取り下げ等) |

## 8. 指標一覧

| 区分 | 指標 |
|---|---|
| 封じ込め | リスクスコア、境界への圧力、境界違反、認証情報の増幅、攻撃チェーンの深さ、検知遅延、アラートから停止までの遅延、アラート後の被害範囲、阻止イベント数、セキュリティ不変条件の維持、トポロジ違反 |
| 多層防御 | 独立防御の故障確率 |
| 学習 | エピソード間の傾向変化 |
| 脅威インテリジェンス | 捏造 advisory の受理率、正当 advisory の受理率、検証カバレッジ、不要な修正対応の件数、訂正までの遅延 |

## 9. 実行方法

評価メニューからの実行(推奨):

```powershell
python scripts/evaluate.py agentic      # 6シナリオのベンチマーク
python scripts/evaluate.py resilience   # 5 seed × 6防御モードの統計比較
```

シナリオを1件ずつ実行する場合:

```powershell
python scripts/run_scenario.py scenarios/agentic/hugging_face_style_containment.json
python scripts/run_scenario.py scenarios/agentic/hybrid_ransom_swarm.json
python scripts/run_scenario.py scenarios/agentic/unit42_autonomous_intrusion.json
python scripts/run_scenario.py scenarios/agentic/rsi_deceptive_takeoff.json
python scripts/run_scenario.py scenarios/agentic/fabricated_cve_integrity.json
```

ベンチマーク全体:

```powershell
python scripts/run_scenario.py benchmarks/cybermatch_agentic_security_v1.json --output-dir output/my-agentic-run
```

出力は canonical JSON と、人が読むための Markdown レポート(`AGENTIC_SECURITY_REPORT.md`)です。既存の出力ディレクトリは上書きされません。

## 10. 参考文献と解釈

- [OpenAI - Hugging Face Incident Technical Report](https://cdn.openai.com/pdf/67869394-cb91-4c12-888c-5cbd85c7814c/OpenAI-Hugging-Face%20Incident-Technical-Report.pdf)
- [Palo Alto Networks Unit 42: Investigation of Single Attacker 10-Hour Intrusion](https://unit42.paloaltonetworks.com/)
- [Arctic Wolf Networks & ZDNet: Cyber Resilience and AI in Japan and Globally](https://japan.zdnet.com/article/35252497/)
- [警察庁 サイバー警察局: ランサムウェア対策](https://www.npa.go.jp/bureau/cyber/countermeasures/ransom.html)
- [Hubinger et al.: Risks from Learned Optimization in Advanced Machine Learning Systems (Mesa-Optimization)](https://arxiv.org/abs/1906.01820)
- [Anthropic: Sleeper Agents: Training Deceptive LLMs that Persist Through Safety Training](https://arxiv.org/abs/2401.05566)
- [JFrog: SQLite Critical CVEs or LLM Slop?](https://research.jfrog.com/post/sqlite-critical-cves-or-llm-slops/)
- [SQLite vulnerability status](https://sqlite.org/cves.html)

CyberMatch のシナリオは比較評価のための**抽象化**です。元となったインシデントの技術的・組織的な詳細をすべて再現するものではありません。
