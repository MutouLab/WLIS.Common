using System;

namespace MutouLab.WLIS.Common.Cryptography
{
    /// <summary>
    /// Udon互換の256bit符号なし整数構造体。
    /// ECDSA(secp256r1等)の公開鍵検証のために用いる。
    /// Udonの制約上、ヒープアロケーションを避けるため値型(struct)かつ8つの32bit型フィールドで表現する。
    /// リトルエンディアン（v0 が最下位32bit, v7 が最上位32bit）。
    /// </summary>
    public struct UInt256
    {
        public uint v0, v1, v2, v3, v4, v5, v6, v7;

        public UInt256(uint _v0, uint _v1, uint _v2, uint _v3, uint _v4, uint _v5, uint _v6, uint _v7)
        {
            v0 = _v0; v1 = _v1; v2 = _v2; v3 = _v3;
            v4 = _v4; v5 = _v5; v6 = _v6; v7 = _v7;
        }

        public static readonly UInt256 Zero = new UInt256(0, 0, 0, 0, 0, 0, 0, 0);
        public static readonly UInt256 One  = new UInt256(1, 0, 0, 0, 0, 0, 0, 0);

        public bool IsZero => (v0 | v1 | v2 | v3 | v4 | v5 | v6 | v7) == 0;
        public bool IsEven => (v0 & 1) == 0;

        // --- 比較演算 ---
        public static int Compare(UInt256 a, UInt256 b)
        {
            if (a.v7 != b.v7) return a.v7 < b.v7 ? -1 : 1;
            if (a.v6 != b.v6) return a.v6 < b.v6 ? -1 : 1;
            if (a.v5 != b.v5) return a.v5 < b.v5 ? -1 : 1;
            if (a.v4 != b.v4) return a.v4 < b.v4 ? -1 : 1;
            if (a.v3 != b.v3) return a.v3 < b.v3 ? -1 : 1;
            if (a.v2 != b.v2) return a.v2 < b.v2 ? -1 : 1;
            if (a.v1 != b.v1) return a.v1 < b.v1 ? -1 : 1;
            if (a.v0 != b.v0) return a.v0 < b.v0 ? -1 : 1;
            return 0;
        }

        public static bool Equals(UInt256 a, UInt256 b)
        {
            return a.v0 == b.v0 && a.v1 == b.v1 && a.v2 == b.v2 && a.v3 == b.v3 &&
                   a.v4 == b.v4 && a.v5 == b.v5 && a.v6 == b.v6 && a.v7 == b.v7;
        }

        // --- 基本演算 ---
        public static UInt256 Add(UInt256 a, UInt256 b, out uint carry)
        {
            ulong sum = (ulong)a.v0 + b.v0;
            uint r0 = (uint)sum;
            sum = (ulong)a.v1 + b.v1 + (sum >> 32);
            uint r1 = (uint)sum;
            sum = (ulong)a.v2 + b.v2 + (sum >> 32);
            uint r2 = (uint)sum;
            sum = (ulong)a.v3 + b.v3 + (sum >> 32);
            uint r3 = (uint)sum;
            sum = (ulong)a.v4 + b.v4 + (sum >> 32);
            uint r4 = (uint)sum;
            sum = (ulong)a.v5 + b.v5 + (sum >> 32);
            uint r5 = (uint)sum;
            sum = (ulong)a.v6 + b.v6 + (sum >> 32);
            uint r6 = (uint)sum;
            sum = (ulong)a.v7 + b.v7 + (sum >> 32);
            uint r7 = (uint)sum;
            
            carry = (uint)(sum >> 32);
            return new UInt256(r0, r1, r2, r3, r4, r5, r6, r7);
        }

        public static UInt256 Sub(UInt256 a, UInt256 b, out uint borrow)
        {
            long diff = (long)a.v0 - b.v0;
            uint r0 = (uint)diff;
            diff = (long)a.v1 - b.v1 + (diff >> 32);
            uint r1 = (uint)diff;
            diff = (long)a.v2 - b.v2 + (diff >> 32);
            uint r2 = (uint)diff;
            diff = (long)a.v3 - b.v3 + (diff >> 32);
            uint r3 = (uint)diff;
            diff = (long)a.v4 - b.v4 + (diff >> 32);
            uint r4 = (uint)diff;
            diff = (long)a.v5 - b.v5 + (diff >> 32);
            uint r5 = (uint)diff;
            diff = (long)a.v6 - b.v6 + (diff >> 32);
            uint r6 = (uint)diff;
            diff = (long)a.v7 - b.v7 + (diff >> 32);
            uint r7 = (uint)diff;
            
            borrow = (diff >> 32) != 0 ? 1u : 0u;
            return new UInt256(r0, r1, r2, r3, r4, r5, r6, r7);
        }

        public static UInt256 ShiftRight1(UInt256 a)
        {
            return new UInt256(
                (a.v0 >> 1) | (a.v1 << 31),
                (a.v1 >> 1) | (a.v2 << 31),
                (a.v2 >> 1) | (a.v3 << 31),
                (a.v3 >> 1) | (a.v4 << 31),
                (a.v4 >> 1) | (a.v5 << 31),
                (a.v5 >> 1) | (a.v6 << 31),
                (a.v6 >> 1) | (a.v7 << 31),
                (a.v7 >> 1)
            );
        }

        public bool GetBit(int index)
        {
            if (index < 0 || index >= 256) return false;
            int word = index / 32;
            int bit = index % 32;
            switch(word)
            {
                case 0: return ((v0 >> bit) & 1) == 1;
                case 1: return ((v1 >> bit) & 1) == 1;
                case 2: return ((v2 >> bit) & 1) == 1;
                case 3: return ((v3 >> bit) & 1) == 1;
                case 4: return ((v4 >> bit) & 1) == 1;
                case 5: return ((v5 >> bit) & 1) == 1;
                case 6: return ((v6 >> bit) & 1) == 1;
                case 7: return ((v7 >> bit) & 1) == 1;
                default: return false;
            }
        }

        // --- 剰余演算 (Modulo Arithmetic) ---
        public static UInt256 AddMod(UInt256 a, UInt256 b, UInt256 m)
        {
            UInt256 sum = Add(a, b, out uint carry);
            if (carry != 0 || Compare(sum, m) >= 0)
            {
                sum = Sub(sum, m, out _);
            }
            return sum;
        }

        public static UInt256 SubMod(UInt256 a, UInt256 b, UInt256 m)
        {
            UInt256 diff = Sub(a, b, out uint borrow);
            if (borrow != 0)
            {
                diff = Add(diff, m, out _);
            }
            return diff;
        }

        // bit-by-bit の軽量モジュラ乗算（Udonの1フレーム制限に配慮）
        public static UInt256 MulMod(UInt256 a, UInt256 b, UInt256 m)
        {
            UInt256 res = Zero;
            UInt256 tempA = a;
            
            for (int i = 0; i < 256; i++)
            {
                if (b.GetBit(i))
                {
                    res = AddMod(res, tempA, m);
                }
                tempA = AddMod(tempA, tempA, m); // tempA = (tempA * 2) mod m
            }
            return res;
        }

        // バイナリ拡張ユークリッド互除法によるモジュラ逆元 (Binary Extended Euclidean Algorithm)
        public static UInt256 ModInverse(UInt256 a, UInt256 m)
        {
            if (a.IsZero) return Zero;

            UInt256 u = a, v = m;
            UInt256 x1 = One, x2 = Zero;

            while (!u.IsZero && !v.IsZero)
            {
                while (u.IsEven)
                {
                    u = ShiftRight1(u);
                    if (x1.IsEven)
                    {
                        x1 = ShiftRight1(x1);
                    }
                    else
                    {
                        x1 = Add(x1, m, out uint carry);
                        x1 = ShiftRight1(x1);
                        if (carry != 0) x1.v7 |= 0x80000000;
                    }
                }
                while (v.IsEven)
                {
                    v = ShiftRight1(v);
                    if (x2.IsEven)
                    {
                        x2 = ShiftRight1(x2);
                    }
                    else
                    {
                        x2 = Add(x2, m, out uint carry);
                        x2 = ShiftRight1(x2);
                        if (carry != 0) x2.v7 |= 0x80000000;
                    }
                }

                if (Compare(u, v) >= 0)
                {
                    u = Sub(u, v, out _);
                    x1 = SubMod(x1, x2, m);
                }
                else
                {
                    v = Sub(v, u, out _);
                    x2 = SubMod(x2, x1, m);
                }
            }
            return u.IsZero ? x2 : x1;
        }

        // --- パース/フォーマット ---
        public static UInt256 ParseHex(string hex)
        {
            if (string.IsNullOrEmpty(hex)) return Zero;
            hex = hex.Replace("0x", "").Replace(" ", "").Replace("-", "").ToUpperInvariant();
            if (hex.Length > 64) hex = hex.Substring(hex.Length - 64);
            hex = hex.PadLeft(64, '0');

            return new UInt256(
                Convert.ToUInt32(hex.Substring(56, 8), 16),
                Convert.ToUInt32(hex.Substring(48, 8), 16),
                Convert.ToUInt32(hex.Substring(40, 8), 16),
                Convert.ToUInt32(hex.Substring(32, 8), 16),
                Convert.ToUInt32(hex.Substring(24, 8), 16),
                Convert.ToUInt32(hex.Substring(16, 8), 16),
                Convert.ToUInt32(hex.Substring(8, 8), 16),
                Convert.ToUInt32(hex.Substring(0, 8), 16)
            );
        }

        public override string ToString()
        {
            return $"{v7:X8}{v6:X8}{v5:X8}{v4:X8}{v3:X8}{v2:X8}{v1:X8}{v0:X8}";
        }
    }
}
