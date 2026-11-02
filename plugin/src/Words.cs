using System.Collections.Generic;

namespace Hd2Qd.License
{
    /// <summary>The plugin's words, (English, Chinese); the manager says which language.</summary>
    static class Words
    {
        static readonly Dictionary<string, (string En, string Zh)> T = new Dictionary<string, (string, string)>
        {
            ["lic_title"] = ("Member licenses", "会员授权"),
            ["lic_intro"] = ("Some mods are available only to their author's members. Sign in to the author's site once; this program renews the license before it expires.",
                             "部分 MOD 仅供作者的会员使用。首次使用需在作者的网站登录，授权到期前由本程序自动续期。"),
            ["lic_licensed"] = ("Licensed until {0}", "已授权，有效期至 {0}"),
            ["lic_expired"] = ("Expired on {0}", "已于 {0} 过期"),
            ["lic_none"] = ("Not signed in", "未登录"),
            ["lic_other_account"] = ("The license on this computer is for another game account", "此电脑上的授权属于另一个游戏账号"),
            ["lic_invalid"] = ("The license on this computer is not signed by this author's key", "此电脑上的授权不是由该作者的密钥签发的"),
            ["lic_key_changed"] = ("A mod declares a different key for this author. Check where it came from.", "有 MOD 为该作者声明了不同的密钥，请确认其来源。"),
            ["lic_no_account"] = ("There is no game account on this computer yet. Start the game once.", "此电脑上尚无游戏账号，请先启动一次游戏。"),
            ["lic_bad_declaration"] = ("This mod's license declaration (hd2_license.json) cannot be read.", "无法读取此 MOD 的授权声明（hd2_license.json）。"),
            ["lic_mods"] = ("Mods: {0}", "MOD：{0}"),
            ["lic_nothing"] = ("No mod in the library requires a license, and no author is signed in on this computer.",
                               "库中暂无需要授权的 MOD，此电脑上也未登录任何作者。"),
            ["lic_no_mods"] = ("No mod in the library currently requires this license", "库中暂无需要此授权的 MOD"),
            ["lic_sign_in"] = ("Sign in", "登录"),
            ["lic_sign_in_again"] = ("Sign in again", "重新登录"),
            ["lic_sign_out"] = ("Sign out", "退出登录"),
            ["lic_ask"] = ("Your browser will open {0}, the site of {1}. That site receives your game account ID ({2}).",
                           "浏览器将打开 {1} 的网站 {0}，该网站将获得你的游戏账号标识（{2}）。"),
            ["lic_waiting"] = ("Waiting for the sign-in in your browser…", "正在等待浏览器中的登录…"),
            ["lic_done"] = ("Licensed until {0}.", "授权完成，有效期至 {0}。"),
            ["lic_cancelled"] = ("The sign-in was cancelled.", "已取消登录。"),
            ["lic_sign_out_ask"] = ("Remove this author's license and sign-in from this computer? Their mods will not work until you sign in again.",
                                    "是否从此电脑移除该作者的授权与登录信息？重新登录前，该作者的 MOD 将无法使用。"),
            ["lic_err_not_member"] = ("This account is not an active member, or its tier is too low.", "此账号不是有效会员，或会员档位不足。"),
            ["lic_err_account_limit"] = ("This membership already has as many game accounts as the author allows. Contact the author.",
                                         "此会员绑定的游戏账号已达作者允许的上限，请联系作者。"),
            ["lic_err_denied"] = ("Access was not granted on the author's site.", "未在作者的网站上授予权限。"),
            ["lic_err_timeout"] = ("The sign-in did not finish within 10 minutes.", "登录未在 10 分钟内完成。"),
            ["lic_err_network"] = ("The author's site cannot be reached.", "无法连接作者的网站。"),
            ["lic_err_bad_license"] = ("The license received is not signed by the key the mod declares.", "收到的授权与 MOD 声明的密钥不符。"),
            ["lic_err_key_changed"] = ("A mod declares a different key for this author. Check where it came from.", "有 MOD 为该作者声明了不同的密钥，请确认其来源。"),
            ["lic_err_sign_in_again"] = ("The author's site asks you to sign in again.", "作者的网站要求重新登录。"),
            ["lic_err_other"] = ("The sign-in failed: {0}", "登录失败：{0}"),
            ["row_license"] = ("Needs a license", "需要授权"),
            ["row_license_expired"] = ("License expired", "授权已过期"),
            ["row_license_tip"] = ("For the author's members: sign in on the Plugins page (the jigsaw piece beside the gear).", "仅供作者的会员使用：请在「插件」页登录（齿轮旁的拼图按钮）。"),
            ["cancel"] = ("Cancel", "取消"),
            ["failed"] = ("Failed: {0}", "失败：{0}"),
        };

        public static string Get(string key, bool zh) => T.TryGetValue(key, out var p) ? (zh ? p.Zh : p.En) : key;
        public static string F(string key, bool zh, params object[] args) => string.Format(Get(key, zh), args);
    }
}
