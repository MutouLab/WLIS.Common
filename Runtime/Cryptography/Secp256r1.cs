namespace MutouLab.WLIS.Common.Cryptography
{
    /// <summary>
    /// NIST P-256 (secp256r1) の固定パラメータ群
    /// </summary>
    public static class Secp256r1
    {
        // 楕円曲線の素数 P
        public static readonly UInt256 P = UInt256.ParseHex("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF");

        // ベースポイントの位数 N
        public static readonly UInt256 N = UInt256.ParseHex("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");

        // 曲線パラメータ A (-3)
        // A = P - 3
        public static readonly UInt256 A = UInt256.ParseHex("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC");

        // 曲線パラメータ B
        public static readonly UInt256 B = UInt256.ParseHex("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B");

        // ベースポイント G
        public static readonly ECPoint G = new ECPoint(
            UInt256.ParseHex("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"),
            UInt256.ParseHex("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"),
            false
        );
    }
}
