namespace MutouLab.WLIS.Common
{
    /// <summary>
    /// ペイロードフィールドのデータ型指定。
    /// エディタツール間の共有定義。Udonランタイム側にも同一定義あり。
    /// </summary>
    public enum PayloadInputMode
    {
        Bool,
        Int,
        Float,
        Vector3,
    }
}