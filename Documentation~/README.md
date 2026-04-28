# WLIS Common

World Linked Item System の共通ライブラリ。  
WorldSide / AvatarSide 両プロジェクトが共有する暗号プリミティブ、ユーティリティ、エディタツール共通コードを含みます。

## 含まれるアセンブリ

### Runtime: `MutouLab.WLIS.Common`
- `ConflictResolveMode` — 競合解決モード列挙型
- `PayloadInputMode` — ペイロード入力モード列挙型
- `WLISStringUtility` — FNV-1aハッシュ、文字列正規化
- `Cryptography/TEACipher` — TEA暗号コア
- `Cryptography/UInt256` — 256bit整数演算
- `Cryptography/ECPoint` — 楕円曲線上の点演算
- `Cryptography/Secp256r1` — NIST P-256カーブパラメータ

### Editor: `MutouLab.WLIS.Tools.Common.Editor`
- `CryptographyType` — TEA/ECDSA_P256列挙型
- `WLISItemTargetProfile` — アイテム作者向け配布プロファイル
- `ECDSASignatureUtility` — ECDSA署名・鍵生成ユーティリティ

## インストール

### VCC (VRChat Creator Companion)
以下のURLをVCCのリポジトリに追加してください：
```
https://mutoulab.github.io/WLIS.Common/index.json
```
