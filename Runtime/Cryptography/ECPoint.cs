using System;

namespace MutouLab.WLIS.Common.Cryptography
{
    /// <summary>
    /// 楕円曲線上の点を表現する構造体(アフィン座標系)。
    /// Udon環境でのアロケーションレスな演算を行うため構造体をベースに実装。
    /// </summary>
    public struct ECPoint
    {
        public UInt256 X;
        public UInt256 Y;
        public bool IsInfinity;

        public ECPoint(UInt256 x, UInt256 y, bool isInfinity = false)
        {
            X = x;
            Y = y;
            IsInfinity = isInfinity;
        }

        public static readonly ECPoint Infinity = new ECPoint(UInt256.Zero, UInt256.Zero, true);

        public static bool Equals(ECPoint a, ECPoint b)
        {
            if (a.IsInfinity && b.IsInfinity) return true;
            if (a.IsInfinity || b.IsInfinity) return false;
            return UInt256.Equals(a.X, b.X) && UInt256.Equals(a.Y, b.Y);
        }

        // --- 楕円曲線の点加算 ---
        public static ECPoint Add(ECPoint p, ECPoint q)
        {
            if (p.IsInfinity) return q;
            if (q.IsInfinity) return p;

            if (UInt256.Equals(p.X, q.X))
            {
                if (UInt256.Equals(p.Y, q.Y))
                    return Double(p);
                else
                    return Infinity; // P + (-P) = O
            }

            UInt256 P_prime = Secp256r1.P;

            // dy = q.y - p.y
            UInt256 dy = UInt256.SubMod(q.Y, p.Y, P_prime);
            // dx = q.x - p.x
            UInt256 dx = UInt256.SubMod(q.X, p.X, P_prime);

            // lambda = dy * modInverse(dx)
            UInt256 dxInv = UInt256.ModInverse(dx, P_prime);
            UInt256 lambda = UInt256.MulMod(dy, dxInv, P_prime);

            // xr = lambda^2 - p.x - q.x
            UInt256 lambdaSq = UInt256.MulMod(lambda, lambda, P_prime);
            UInt256 xr = UInt256.SubMod(lambdaSq, p.X, P_prime);
            xr = UInt256.SubMod(xr, q.X, P_prime);

            // yr = lambda * (p.x - xr) - p.y
            UInt256 dxr = UInt256.SubMod(p.X, xr, P_prime);
            UInt256 yr = UInt256.MulMod(lambda, dxr, P_prime);
            yr = UInt256.SubMod(yr, p.Y, P_prime);

            return new ECPoint(xr, yr);
        }

        // --- 楕円曲線の点2倍算 ---
        public static ECPoint Double(ECPoint p)
        {
            if (p.IsInfinity || p.Y.IsZero) return Infinity;

            UInt256 P_prime = Secp256r1.P;

            // lambda = (3 * p.x^2 + A) / (2 * p.y)
            UInt256 xSq = UInt256.MulMod(p.X, p.X, P_prime);
            UInt256 threeXSq = UInt256.AddMod(xSq, UInt256.AddMod(xSq, xSq, P_prime), P_prime); // 3*x^2
            UInt256 num = UInt256.AddMod(threeXSq, Secp256r1.A, P_prime);

            UInt256 den = UInt256.AddMod(p.Y, p.Y, P_prime); // 2*y
            UInt256 denInv = UInt256.ModInverse(den, P_prime);

            UInt256 lambda = UInt256.MulMod(num, denInv, P_prime);

            // xr = lambda^2 - 2*p.x
            UInt256 lambdaSq = UInt256.MulMod(lambda, lambda, P_prime);
            UInt256 twoX = UInt256.AddMod(p.X, p.X, P_prime);
            UInt256 xr = UInt256.SubMod(lambdaSq, twoX, P_prime);

            // yr = lambda * (p.x - xr) - p.y
            UInt256 dxr = UInt256.SubMod(p.X, xr, P_prime);
            UInt256 yr = UInt256.MulMod(lambda, dxr, P_prime);
            yr = UInt256.SubMod(yr, p.Y, P_prime);

            return new ECPoint(xr, yr);
        }
        
        public override string ToString()
        {
            if (IsInfinity) return "Infinity";
            return $"({X.ToString()}, {Y.ToString()})";
        }
    }
}
