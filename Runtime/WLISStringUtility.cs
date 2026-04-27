using System;

namespace MutouLab.WLIS.Common
{
    /// <summary>
    /// WLISの文字列処理（ハッシュ化や正規化等）を提供する静的ユーティリティクラス
    /// ランタイム(Udon)およびエディタツールの両方から参照されます。
    /// </summary>
    public static class WLISStringUtility
    {
        /// <summary>
        /// プラットフォーム非依存の文字列ハッシュ（FNV-1a）
        /// .NET/Mono/Udon VM 間で同一の結果を保証する。
        /// </summary>
        public static int DeterministicStringHash(string str)
        {
            uint h = 0x811C9DC5; // FNV-1a offset basis
            if (!string.IsNullOrEmpty(str))
            {
                for (int i = 0; i < str.Length; i++)
                {
                    h ^= (uint)str[i];
                    h *= 0x01000193; // FNV-1a prime
                }
            }
            return (int)h;
        }

        /// <summary>
        /// Player MAC計算等に用いる表示名の正規化処理（小文字化、全角/半角スペース除去）
        /// </summary>
        public static string NormalizePlayerName(string rawName)
        {
            if (string.IsNullOrEmpty(rawName)) return "";
            return rawName.ToLowerInvariant().Replace(" ", "").Replace("　", "").Trim();
        }
    }
}
