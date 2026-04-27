using System;
using System.Text;
using System.Security.Cryptography;

namespace MutouLab.WLIS.Tools.Common.Editor
{
    /// <summary>
    /// WLIS: エディタ用の ECDSA(secp256r1) 署名生成・鍵生成ユーティリティ。
    /// 生成された公開鍵/秘密鍵はBase64ではなく16進数(Hex)文字列として扱われ、Udon側の UInt256 エンジンと連携します。
    /// </summary>
    public static class ECDSASignatureUtility
    {
        /// <summary>
        /// secp256r1 の秘密鍵(D)と公開鍵(X, Y)を生成し、それぞれHex文字列(64文字)として返す。
        /// </summary>
        public static void GenerateKeyPair(out string privateKeyHex, out string publicKeyXHex, out string publicKeyYHex)
        {
            using (var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256))
            {
                var parameters = ecdsa.ExportParameters(true);

                privateKeyHex = BytesToHex(parameters.D);
                publicKeyXHex = BytesToHex(parameters.Q.X);
                publicKeyYHex = BytesToHex(parameters.Q.Y);
            }
        }

        /// <summary>
        /// 提供された秘密鍵を用いて、WLISペイロードの署名（r, s）を生成し、
        /// Udon側が受信・検証可能な16要素のint配列（64byte）に変換して返す。
        /// </summary>
        public static int[] SignPayload(int[] payloadData, int payloadLength, int itemID, string privateKeyHex)
        {
            // 1. ハッシュを計算 (WLISECDSAEngine.CalculatePayloadHash と完全に一致させる)
            byte[] hashZ = CalculatePayloadHashBytes(payloadData, payloadLength, itemID);

            // 2. 秘密鍵パラメータを組み立てる
            byte[] dBytes = HexToBytes(privateKeyHex);
            var curve = ECCurve.NamedCurves.nistP256;
            
            // 公開鍵を導出する必要があるためCngKeyを使うか、ダミーを入れるか。
            // 署名だけなら Q は厳密には必須ではないが、ECDsa.Create(param) ではQが必須となる実装が多い。
            // (Windows限定ならCngKeyが使えるが、Mac等との互換を考慮して秘密鍵からダミーを生成するより一時インスタンスを使う)
            byte[] signatureBytes;
            using (var ecdsa = ECDsa.Create())
            {
                // .NET Standard 2.0/2.1 で秘密鍵のみインポートする簡便な方法は ImportECPrivateKey 等だが
                // 手動構成が必要。
                // 簡略化：ECDsa.Create(ECCurve) は新規なので、パラメータを手動注入する
                var parameters = new ECParameters { Curve = curve, D = dBytes };
                // ただし、Dだけあるとエラーになることがあるので、公開鍵を計算せずに署名できる実装に頼る
                // → ECDsa.Create(parameters) が失敗する場合は回避策が必要。
                try
                {
                    ecdsa.ImportParameters(parameters);
                    signatureBytes = ecdsa.SignHash(hashZ); // (r,s) が計64バイトのビッグエンディアン配列で返される
                }
                catch
                {
                    // フォールバック: Windows CngKey等に頼らず、手動でやり直すか、本来はBouncyCastleを使うのが安全。
                    // .NET の ECDsa 実装によっては D のみでの ImportParameters を許容する。
                    throw new InvalidOperationException("[WLIS ECDSA] 秘密鍵からの署名生成に失敗しました。");
                }
            }

            // signatureBytes は 64バイト (先頭32Bがr、後半32Bがs)
            // これを 16個の int に詰め替える (WLISECDSAEngine のシリアライズに合わせる)
            // WLISECDSAEngine では：
            // _r = new UInt256( signature[7], signature[6], signature[5], signature[4], signature[3], signature[2], signature[1], signature[0] )
            // すなわち、signature[0] が r のリトルエンディアン最下位（v0）、signature[7] が最上位（v7）。
            int[] outSignature = new int[16];

            byte[] rBytes = new byte[32];
            byte[] sBytes = new byte[32];
            Array.Copy(signatureBytes, 0, rBytes, 0, 32);
            Array.Copy(signatureBytes, 32, sBytes, 0, 32);

            // ビッグエンディアンのバイト配列(rBytes)を32bit(uint)の配列に変換し、リトルエンディアンでv0~v7に割り当てる
            for (int i = 0; i < 8; i++)
            {
                // rBytes[31]が最下位バイト
                int offsetR = 32 - 4 - (i * 4); 
                outSignature[i] = (rBytes[offsetR] << 24) | (rBytes[offsetR + 1] << 16) | (rBytes[offsetR + 2] << 8) | rBytes[offsetR + 3];

                int offsetS = 32 - 4 - (i * 4);
                outSignature[i + 8] = (sBytes[offsetS] << 24) | (sBytes[offsetS + 1] << 16) | (sBytes[offsetS + 2] << 8) | sBytes[offsetS + 3];
            }

            return outSignature;
        }

        // WLISECDSAEngine.CalculatePayloadHash と完全に一致するロジック
        private static byte[] CalculatePayloadHashBytes(int[] data, int length, int itemID)
        {
            uint h0 = 0x811c9dc5, h1 = 0x811c9dc5, h2 = 0x811c9dc5, h3 = 0x811c9dc5;
            uint h4 = 0x811c9dc5, h5 = 0x811c9dc5, h6 = 0x811c9dc5, h7 = 0x811c9dc5;
            uint prime = 0x01000193;

            h0 ^= (uint)itemID; h0 *= prime;

            for (int i = 0; i < length; i++)
            {
                uint d = (uint)data[i];
                if(i % 8 == 0) { h0 ^= d; h0 *= prime; }
                if(i % 8 == 1) { h1 ^= d; h1 *= prime; }
                if(i % 8 == 2) { h2 ^= d; h2 *= prime; }
                if(i % 8 == 3) { h3 ^= d; h3 *= prime; }
                if(i % 8 == 4) { h4 ^= d; h4 *= prime; }
                if(i % 8 == 5) { h5 ^= d; h5 *= prime; }
                if(i % 8 == 6) { h6 ^= d; h6 *= prime; }
                if(i % 8 == 7) { h7 ^= d; h7 *= prime; }
            }

            // バイト配列(32bytes・ビッグエンディアン)にパッキングする
            // UInt256.ParseHex等の処理と合わせ、v7(最上位)からv0(最下位)の順になるよう配置
            byte[] zBytes = new byte[32];
            PackUintToBytes(h7, zBytes, 0);
            PackUintToBytes(h6, zBytes, 4);
            PackUintToBytes(h5, zBytes, 8);
            PackUintToBytes(h4, zBytes, 12);
            PackUintToBytes(h3, zBytes, 16);
            PackUintToBytes(h2, zBytes, 20);
            PackUintToBytes(h1, zBytes, 24);
            PackUintToBytes(h0, zBytes, 28);

            return zBytes;
        }

        private static void PackUintToBytes(uint val, byte[] buf, int offset)
        {
            buf[offset + 0] = (byte)((val >> 24) & 0xFF);
            buf[offset + 1] = (byte)((val >> 16) & 0xFF);
            buf[offset + 2] = (byte)((val >> 8) & 0xFF);
            buf[offset + 3] = (byte)(val & 0xFF);
        }

        private static string BytesToHex(byte[] bytes)
        {
            if (bytes == null) return string.Empty;
            var sb = new StringBuilder(bytes.Length * 2);
            foreach (var b in bytes)
            {
                sb.Append(b.ToString("X2"));
            }
            return sb.ToString();
        }

        private static byte[] HexToBytes(string hex)
        {
            if (string.IsNullOrEmpty(hex)) return new byte[0];
            byte[] bytes = new byte[hex.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
            {
                bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            }
            return bytes;
        }
    }
}
