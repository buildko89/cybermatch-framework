# CyberMatch LOCAL-1 モデル配置場所

このディレクトリは、LOCAL-1(ローカル LLM による説明生成)用モデルの**固定インストール先**です。
GGUF ファイル本体は意図的に Git 管理外(`.gitignore` 済み)にしています。

| 項目 | 値 |
|---|---|
| モデル | `Qwen2.5-1.5B-Instruct Q4_K_M` |
| ファイル名 | `qwen2.5-1.5b-instruct-q4_k_m.gguf` |
| サイズ | `1117320736` bytes(約1.04 GiB) |
| SHA-256 | `6a1a2eb6d15622bf3c96857206351ba97e1af16c30d7a74ee38970e434e9407e` |
| 入手元 | Hugging Face の `Qwen/Qwen2.5-1.5B-Instruct-GGUF` |

## 導入・検証

| 目的 | コマンド |
|---|---|
| 手元のコピーから導入(ネットワーク不要) | `python scripts/setup_qwen25.py --source <GGUFのパス> --smoke-test` |
| 固定の入手元からダウンロード | `python scripts/setup_qwen25.py --download --smoke-test` |
| 導入済みモデルの検証 | `python scripts/setup_qwen25.py --smoke-test` |
| オプション一覧 | `python scripts/setup_qwen25.py --help` |

セットアップはサイズと SHA-256 を厳密に照合してから、アトミックに配置します。任意の URL からのダウンロードは受け付けません。
`--smoke-test` には `llama-cpp-python` が必要です(`python -m pip install -e ".[local-llm]"`)。

> LOCAL-1 で承認されているのはこの Qwen モデルだけです。Llama 系モデルの導入は保留(対象外)としています。

利用方法は [03 外部評価実行手順書 8.3](../../docs/03_external_evaluation_guide.md#83-local-qwenを導入する) を参照してください。
