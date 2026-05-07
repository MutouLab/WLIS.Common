using UnityEngine;
using MutouLab.WLIS.Common;

namespace MutouLab.WLIS.Tools.Common.Editor
{
    /// <summary>
    /// WLIS: クリエイター鍵（MAC生成・署名用）の配布・保存用プロファイル
    /// </summary>
    public class WLISCreatorKeyProfile : ScriptableObject
    {
        public string WorldName = "";
        public string ItemName = "";
        public string ExportDate = "";
        public CryptographyType CryptoType = CryptographyType.TEA;
        public string SharedCreatorKey = "";
        public string EcdsaPrivateKeyHex = "";
    }
}
