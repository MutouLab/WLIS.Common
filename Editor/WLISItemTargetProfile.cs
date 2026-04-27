using UnityEngine;

using MutouLab.WLIS.Common;

namespace MutouLab.WLIS.Tools.Common.Editor
{
    /// <summary>
    /// WLIS: アイテム作者への配布用データ・プロファイル（エクスポート用）
    /// ワールド作者からアイテム作者へ渡し、MAC生成ツールの"鍵設定ファイル"として使用する。
    /// </summary>
    public class WLISItemTargetProfile : ScriptableObject
    {
        [Header("Exported Package Info")]
        public string WorldName = "";
        public string ItemName = "";
        public string ExportDate = "";

        [Header("Item Field Parameters")]
        public int TargetItemID = 0; // ItemNameのハッシュ値が入る
        public CryptographyType CryptoType = CryptographyType.TEA;
        public ConflictResolveMode ConflictResolveMode = ConflictResolveMode.Override;
        public int RequiredSize = 1;

        [Header("Payload Layout (Optional)")]
        public string[] PayloadNames;
        public PayloadInputMode[] PayloadTypes;

        [Header("Crypto Keys (For Item Creator)")]
        [Tooltip("MAC生成用の共有鍵 (TEA等)")]
        public string SharedKeyC = "";

        [Tooltip("ECDSA署名用の秘密鍵 (Tier1用 / Hex形式)")]
        public string EcdsaPrivateKeyHex = "";
    }
}
