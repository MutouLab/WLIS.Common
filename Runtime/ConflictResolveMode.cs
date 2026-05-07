namespace MutouLab.WLIS.Common
{
    /// <summary>
    /// ペイロードデータの競合時の解決方法。
    /// エディタツール間の共有定義。Udonランタイム側にも同一定義あり。
    /// </summary>
    public enum ConflictResolveMode
    {
        Override,
        Add,
        Min,
        Max,
        Multiply,
    }
}