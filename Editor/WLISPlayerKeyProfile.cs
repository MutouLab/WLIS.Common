using UnityEngine;
using MutouLab.WLIS.Common;

namespace MutouLab.WLIS.Tools.Common.Editor
{
    /// <summary>
    /// WLIS: プレイヤー鍵（MAC検証用）の配布・保存用プロファイル
    /// </summary>
    public class WLISPlayerKeyProfile : ScriptableObject
    {
        public string WorldName = "";
        public string ExportDate = "";
        public string SharedPlayerKey = "";
    }
}
