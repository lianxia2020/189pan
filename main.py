"""
Secrets：
  TYYP_USERNAME  手机号，多账号用 & 分隔
  TYYP_PSW       密码，多账号用 & 分隔，顺序与用户名对应
  QYWX_KEY       企业微信群机器人 webhook 里的 key 值
"""
import time
import re
import os
import random
import base64
import rsa
import requests
from datetime import datetime

# ===================== 配置 =====================
DRAW_TASKS = [
    ("TASK_SIGNIN",        "每日签到抽奖"),
    ("TASK_SIGNIN_PHOTOS", "相册签到抽奖"),
    ("TASK_2022_FLDFS_KJ", "福利大放送抽奖"),
]
BI_RM = list("0123456789abcdefghijklmnopqrstuvwxyz")
B64MAP = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
WEB_URL, AUTH_URL, API_URL = "https://cloud.189.cn", "https://open.e.189.cn", "https://api.cloud.189.cn"
APP_ID = "8025431004"
RETURN_URL = "https://m.cloud.189.cn/zhuanti/2020/loginErrorPc/index.html"
TIMEOUT = (15, 20)
DEBUG = os.getenv("DEBUG", "").lower() == "true"
# ================================================


def log(msg):
    print(msg, flush=True)


def debug(msg):
    if DEBUG:
        print(f"[DEBUG] {msg}", flush=True)


def int2char(a):
    return BI_RM[a]


def b64tohex(a):
    d, e, c = "", 0, 0
    for ch in a:
        if ch == "=":
            continue
        v = B64MAP.index(ch)
        if e == 0:
            e, c = 1, 3 & v
            d += int2char(v >> 2)
        elif e == 1:
            e, c = 2, 15 & v
            d += int2char(c << 2 | v >> 4)
        elif e == 2:
            e = 3
            d += int2char(c) + int2char(v >> 2)
            c = 3 & v
        else:
            e = 0
            d += int2char(c << 2 | v >> 4) + int2char(15 & v)
    if e == 1:
        d += int2char(c << 2)
    return d


def rsa_encode(pubkey_b64, string):
    pem = f"-----BEGIN PUBLIC KEY-----\n{pubkey_b64}\n-----END PUBLIC KEY-----"
    pubkey = rsa.PublicKey.load_pkcs1_openssl_pem(pem.encode())
    return b64tohex(base64.b64encode(rsa.encrypt(string.encode(), pubkey)).decode())


class LoginError(Exception):
    pass


def _json(r, stage):
    if r.status_code != 200:
        raise LoginError(f"{stage}：HTTP {r.status_code}")
    try:
        return r.json()
    except ValueError:
        raise LoginError(f"{stage}：响应非 JSON")


def login(username, password):
    if not username or not password:
        raise LoginError("账号或密码为空")
    s = requests.Session()
    s.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36",
        "Accept": "*/*",
    })

    r = s.get(WEB_URL + "/api/portal/unifyLoginForPC.action", params={
        "appId": APP_ID, "clientType": "10020", "returnURL": RETURN_URL,
        "timeStamp": str(int(time.time() * 1000)),
    }, timeout=TIMEOUT, allow_redirects=True)
    if r.status_code != 200 or "unifyAccountLogin" not in r.url:
        raise LoginError(f"登录页异常，落点={r.url[:80]}")
    fields, patterns = {}, {
        "captchaToken": r"['\"]captchaToken['\"]\s+value=['\"]([^'\"]+)['\"]",
        "lt":           r"\blt\s*=\s*['\"]([^'\"]+)['\"]",
        "paramId":      r"\bparamId\s*=\s*['\"]([^'\"]+)['\"]",
        "reqId":        r"\breqId\s*=\s*['\"]([^'\"]+)['\"]",
    }
    for name, pat in patterns.items():
        m = re.search(pat, r.text)
        if not m:
            raise LoginError(f"登录页缺少字段：{name}")
        fields[name] = m.group(1)

    conf = _json(s.post(AUTH_URL + "/api/logbox/config/encryptConf.do",
                        data={"appId": APP_ID}, timeout=TIMEOUT), "加密配置")
    enc = conf.get("data") or {}
    if conf.get("result") not in (0, "0") or not enc.get("pubKey") or not enc.get("pre"):
        raise LoginError("加密配置缺少公钥或前缀")
    eu = enc["pre"] + rsa_encode(enc["pubKey"], username)
    ep = enc["pre"] + rsa_encode(enc["pubKey"], password)
    h = {"Referer": AUTH_URL + "/", "lt": fields["lt"], "REQID": fields["reqId"]}

    rc = s.post(AUTH_URL + "/api/logbox/oauth2/needcaptcha.do", headers=h, data={
        "appKey": APP_ID, "accountType": "02", "userName": eu}, timeout=TIMEOUT)
    if rc.status_code != 200 or rc.text.strip() != "0":
        raise LoginError("需要验证码或检查异常")

    d = _json(s.post(AUTH_URL + "/api/logbox/oauth2/loginSubmit.do", headers=h, data={
        "appKey": APP_ID, "accountType": "02", "userName": eu, "password": ep,
        "validateCode": "", "captchaToken": fields["captchaToken"], "dynamicCheck": "FALSE",
        "clientType": "1", "cb_SaveName": "3", "isOauth2": "false",
        "returnUrl": RETURN_URL, "paramId": fields["paramId"],
    }, timeout=TIMEOUT), "密码登录")
    if d.get("result") not in (0, "0") or not d.get("toUrl"):
        raise LoginError(f"登录被拒绝（{d.get('result')}）：{str(d.get('msg', ''))[:120]}")

    r = s.get(API_URL + "/getSessionForPC.action", params={
        "appId": APP_ID, "clientType": "TELEPC", "version": "6.2",
        "channelId": "web_cloud.189.cn", "rand": str(int(time.time() * 1000)),
        "redirectURL": d["toUrl"],
    }, timeout=TIMEOUT, allow_redirects=True)
    m = re.search(r"<sessionKey>([^<]+)</sessionKey>", r.text)
    if not m:
        raise LoginError("未取到 sessionKey")
    s.cloud189_session_key = m.group(1)
    return s


def do_checkin(s):
    r = {"signin": "", "status": "failed", "error": None}
    try:
        d = _json(s.get(WEB_URL + "/mkt/userSign.action", params={
            "sessionKey": s.cloud189_session_key, "rand": str(int(time.time() * 1000)),
            "clientType": "TELEANDROID", "version": "9.0.6", "model": "KB2000",
        }, headers={"Referer": WEB_URL + "/web/main/"}, timeout=TIMEOUT), "签到")
        if "netdiskBonus" not in d or "isSign" not in d:
            raise LoginError("签到响应无效")
        if d["isSign"] is False or d["isSign"] == "false":
            r.update(status="signed", signin=f"签到成功，获得 {d['netdiskBonus']}M 空间")
        else:
            r.update(status="already_signed", signin="今日已签到，本次未重复领取")
    except Exception as e:
        r["error"] = f"签到失败：{type(e).__name__}"
    return r


def do_draw(s):
    out, hdr = [], {
        "User-Agent": "Mozilla/5.0 (Linux; Android 5.1.1; SM-G930K Build/NRD90M; wv) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/74.0.3729.136 "
                      "Mobile Safari/537.36 Ecloud/8.6.3 Android/22 clientId/355325117317828 "
                      "clientModel/SM-G930K imsi/460071114317824 clientChannelId/qq proVersion/1.0.6",
        "Referer": "https://m.cloud.189.cn/zhuanti/2016/sign/index.jsp?albumBackupOpened=1",
        "Host": "m.cloud.189.cn",
    }
    for idx, (tid, name) in enumerate(DRAW_TASKS, 1):
        item = {"task": name, "msg": "", "status": "failed"}
        for attempt in range(2):
            try:
                d = _json(s.get("https://m.cloud.189.cn/v2/drawPrizeMarketDetails.action",
                                params={"taskId": tid, "activityId": "ACT_SIGNIN"},
                                headers=hdr, timeout=TIMEOUT), f"抽奖{idx}")
                if "errorCode" in d and d["errorCode"]:
                    item.update(status="no_chance", msg=f"未中奖/次数不足({d.get('errorCode')})")
                else:
                    item.update(status="won", msg=f"🎉 抽中 {d.get('prizeName', '未知')}")
                break
            except Exception as e:
                item["msg"] = f"异常：{type(e).__name__}"
                if attempt == 0:
                    time.sleep(2)
        out.append(item)
        if idx < len(DRAW_TASKS):
            time.sleep(random.uniform(2, 4))
    return out


def load_accounts():
    names = os.getenv("TYYP_USERNAME", "")
    pwds = os.getenv("TYYP_PSW", "")
    if not names or not pwds:
        raise RuntimeError("TYYP_USERNAME / TYYP_PSW 未设置")
    u, p = names.split("&"), pwds.split("&")
    if len(u) != len(p):
        raise RuntimeError(f"用户名({len(u)})与密码({len(p)})数量不匹配")
    return [{"username": x, "password": y} for x, y in zip(u, p)]


def wecom_url(key):
    """QYWX_KEY 是 webhook 里的 key 值，拼成完整 URL"""
    key = (key or "").strip()
    if not key:
        return None
    if key.startswith("http"):
        return key
    return f"https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key={key}"


def push_wecom(webhook, content):
    if not webhook:
        log("企业微信 webhook 未配置，跳过推送")
        return
    try:
        r = requests.post(webhook, json={"msgtype": "markdown",
                            "markdown": {"content": content}}, timeout=15)
        ok = r.status_code == 200 and r.json().get("errcode") == 0
        log("企业微信推送：" + ("成功" if ok else f"失败 {r.text[:100]}"))
    except Exception as e:
        log(f"企业微信推送异常：{type(e).__name__}")


def mask(u):
    return u[:3] + "***" + u[-2:] if len(u) > 5 else "***"


def main():
    start = datetime.now()
    log(f"# 天翼云盘自动签到抽奖 ｜ 启动：{start:%Y-%m-%d %H:%M:%S}")
    accounts = load_accounts()
    log(f"- 账户数量：{len(accounts)}")
    webhook = wecom_url(os.getenv("QYWX_KEY"))

    results, report = [], [f"## 天翼云盘签到抽奖报告\n> {start:%Y-%m-%d %H:%M:%S}"]
    for i, acc in enumerate(accounts, 1):
        log(f"\n## 账户{i} {mask(acc['username'])}")
        s, out = None, {"username": mask(acc["username"]), "signin": "", "status": "failed", "draws": []}
        try:
            s = login(acc["username"], acc["password"])
            ck = do_checkin(s)
            out.update(status=ck["status"], signin=ck["signin"] or ck["error"])
            log(f"- 签到：{ck['signin'] or ck['error']}")
            draws = do_draw(s)
            out["draws"] = draws
            for j, d in enumerate(draws, 1):
                log(f"- 抽奖{j} [{d['task']}]：{d['msg']}")
        except Exception as e:
            out["signin"] = f"登录失败：{type(e).__name__}"
            log(f"- {out['signin']}")
        finally:
            if s:
                s.close()
        results.append(out)
        report.append(f"### {out['username']}\n- 签到：{out['signin']}")
        for j, d in enumerate(out["draws"], 1):
            report.append(f"- 抽奖{j} [{d['task']}]：{d['msg']}")

    sc = sum(1 for r in results if r["status"] == "signed")
    al = sum(1 for r in results if r["status"] == "already_signed")
    fl = sum(1 for r in results if r["status"] == "failed")
    won = sum(1 for r in results for d in r["draws"] if d["status"] == "won")
    cost = (datetime.now() - start).total_seconds()
    report.insert(1, f"> 🎉 签到 {sc} · ✅ 已签 {al} · ❌ 失败 {fl} · 🎁 中奖 {won} ｜ ⏱ {cost:.1f}s")
    push_wecom(webhook, "\n\n".join(report))
    log(f"\n完成：{cost:.1f}s")


if __name__ == "__main__":
    main()
