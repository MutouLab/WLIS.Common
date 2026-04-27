using System;

namespace MutouLab.WLIS.Common.Cryptography
{
    /// <summary>
    /// TEA (Tiny Encryption Algorithm) のコアアルゴリズムと鍵パース処理を提供する静的クラス。
    /// UdonSharpクラスやUnityEditor拡張等から共通して参照されます。
    /// </summary>
    public static class TEACipher
    {
        /// <summary>
        /// 16進数文字列(16文字)を2要素のint配列（64bit）に変換する
        /// </summary>
        public static void ParseHexKeyToBuffer(string hexKey, int[] outKey)
        {
            if (!string.IsNullOrEmpty(hexKey)) hexKey = hexKey.Replace("-", "").Replace(" ", "").Trim();
            if (string.IsNullOrEmpty(hexKey) || hexKey.Length < 16)
            {
                outKey[0] = 0;
                outKey[1] = 0;
                return;
            }
            outKey[0] = (int)ParseHexUInt32(hexKey.Substring(0, 8));
            outKey[1] = (int)ParseHexUInt32(hexKey.Substring(8, 8));
        }

        private static uint ParseHexUInt32(string hex)
        {
            uint result = 0;
            for (int i = 0; i < hex.Length; i++)
            {
                char c = hex[i];
                uint val = 0;
                if (c >= '0' && c <= '9') val = (uint)(c - '0');
                else if (c >= 'A' && c <= 'F') val = (uint)(c - 'A' + 10);
                else if (c >= 'a' && c <= 'f') val = (uint)(c - 'a' + 10);
                result = (result << 4) | val;
            }
            return result;
        }

        /// <summary>
        /// TEAアルゴリズムで単一intブロックから32bitのMACを生成するコア処理
        /// </summary>
        public static int ComputeTEACore(int data, int[] key)
        {
            uint k0 = (uint)key[0];
            uint k1 = (uint)key[1];
            uint k2 = ~k0;
            uint k3 = ~k1;

            uint v0 = (uint)data;
            uint v1 = 0xDEADBEEF;
            uint sum = 0, delta = 0x9E3779B9;

            for (int round = 0; round < 32; round++)
            {
                sum += delta;
                v0 += ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
                v1 += ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
            }

            return (int)(v0 ^ v1);
        }

        /// <summary>
        /// 可変長int配列をCBC(Cipher Block Chaining)風にTEAで処理し、
        /// 最終的な32bitのチェインMAC（ハッシュ値）を生成する。
        /// </summary>
        public static int ComputeTEAChain(int[] dataArray, int length, int[] key)
        {
            if (dataArray == null || length <= 0) return 0;

            int currentHash = 0; // IV代わり
            for (int i = 0; i < length; i++)
            {
                // 前のブロックの暗号文（ハッシュ）と現在の平文をXORしてからTEA処理
                currentHash = ComputeTEACore(dataArray[i] ^ currentHash, key);
            }
            return currentHash;
        }
    }
}
