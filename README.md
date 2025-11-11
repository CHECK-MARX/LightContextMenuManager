# Light Context Menu Manager

Windows 11 の右クリックメニューを Python 3.11 + PySide6 で整理する管理ツールです。コンテキストメニュー ハンドラーをスキャンし、無効化/有効化、バックアップ/復元、プリセット適用、履歴管理、CSV 出力などをワンストップで提供します。

## セットアップ

1. 依存パッケージをインストールします。
   ```powershell
   pip install -r requirements.txt
   ```
2. 管理者権限でアプリを起動します (初回起動時に UAC 昇格を自動要求)。
   ```powershell
   python -m src.main
   ```

## 主な機能

- **レジストリスキャン**: 下記キーから shellex と shell のハンドラーを収集 (64bit ビュー)。
  - `HKCR\*\shellex\ContextMenuHandlers`
  - `HKCR\Folder\shellex\ContextMenuHandlers`
  - `HKCR\Directory\Background\shellex\ContextMenuHandlers`
  - `HKCR\Drive\shellex\ContextMenuHandlers`
  - 参照用: `HKCR\*\shell`, `HKCR\Folder\shell`
- **有効/無効切替**: キーを `DisabledHandlers` サブキーへ移動して無効化、逆操作で有効化。
- **ツールバー**: 検索、再読み込み、Undo/Redo、バックアップ(.reg)、復元(.reg)、CSV 出力、プリセット適用、Explorer 再起動、テーマ切替 (qdarktheme)。
- **監査ログ**: `settings.json` の `audit_enabled` で ON/OFF を切替。ON 時は操作ごとに `audit/audit_YYYYMMDD.csv` へ追記され、ツールバーの「監査フォルダを開く」からフォルダを開けます。
- **テーブル表示**: QAbstractTableModel + QSortFilterProxyModel による検索/ソート、状態・スコープ・元パス・最終変更日時を表示。
- **非同期処理**: QtConcurrent + QProgressDialog でスキャンや大量操作中も UI がブロックされないようにしています。
- **ログ/例外**: `logs/app.log` にローテーション出力 (1MB ×3)。エラーはダイアログ表示とログ記録を同時に実施。

## プリセット仕様 (`presets/*.json`)

```json
{
  "id": "minimal",
  "label": "Minimal",
  "description": "家庭用の最小構成",
  "rules": [
    {"name_contains": "OneDrive", "scope": "*", "enable": false},
    {"name_contains": "Git", "enable": true}
  ]
}
```
- `rules` は上から順に評価され、最初に一致したルールで ON/OFF を決定します。
- `name_contains` / `scope` / `path_contains` で行フィルタを指定可能。省略時はワイルドカードとみなします。
- プリセット適用前に対象一覧を確認するダイアログを表示し、`有効化/無効化` 件数や変化行 (青=有効化, 赤=無効化) をプレビューできます。

## CSV 仕様

`[名前, スコープ, 状態, レジストリパス, 最終変更日時]` のヘッダーで UTF-8 CSV を出力します。フィルタやソート結果に関係なく現在のテーブル全件をエクスポートします。

## バックアップ / 復元 (.reg)

- 選択行がある場合はそのサブセット、無い場合は全件 (参照専用を除く) を `.reg` 形式で書き出します。
- 復元は `.reg` を解析して必要なキーを再構築し、成功/失敗/スキップ件数をサマリ表示します。
- バックアップ/復元ともに進捗ダイアログで状態を通知します。

## Undo / Redo / 履歴

- 有効/無効操作を最大 100 件までスタック管理。Undo で直前状態へ、Redo で再適用。
- 履歴はアプリ終了時に `logs/history_snapshot.json` へ保存。起動時は読み取りのみで復元し、ステータスバーで読み込み件数を通知します。

## 権限と Explorer 再起動

- 起動時に管理者権限をチェックし、未昇格であれば UAC プロンプトを表示して自己再起動します。
- 変更反映を即時確認したい場合は「Explorer再起動」ボタンで `taskkill` → `explorer` の順に再起動させます。

## テスト

最低限のユニットテストを `tests/` に配置しています。`pytest` で実行できます。
```powershell
pytest
```

## PyInstaller での単一 EXE 化

以下は GUI (ウィンドウ) 用の例です。
```powershell
pyinstaller -F -w src/main.py -n LightMenuManager
```

## 配布

1. PowerShell でリポジトリルートに移動し、ビルドスクリプトを実行します。
   ```powershell
   pwsh -File scripts/build_exe.ps1
   ```
   - `.venv` が無い場合は自動作成し、`requirements.txt` と `PyInstaller` をインストールします。
   - `assets/app.ico` が存在すればアイコン付きでビルドされます。
2. 成果物は `dist/LightContextMenuManager.exe` に生成され、同階層へ `presets/` と `README.md` がコピーされます。配布時はこのフォルダ一式をまとめて渡してください。
3. EXE 実行時はレジストリアクセスのため **管理者権限での起動が推奨** です (右クリック→「管理者として実行」)。

### 注意事項
- Windows Defender SmartScreen や EDR により未署名 EXE がブロックされる場合があります。配布前にコード署名を行う、または利用環境で発行元を信頼済みに追加・除外ポリシーへ登録してください。
- 署名が難しい場合は、配布先に対して「詳細情報 > 実行」を案内し、配布元を明記した ZIP に同梱することで誤検知を回避しやすくなります。
