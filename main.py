import time
import re
import os
import json
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
WEB_URL  = "https://cloud.189.cn"
AUTH_URL = "https://open.e.189.cn"
API_URL  = "https://api.cloud.189.cn"
APP_ID   = "8025431004"
RETURN_URL = "https://m.cloud.189.cn/zhuanti/2020/loginErrorPc/index.html"
TIMEOUT  = (15, 20)
DEBUG = os.getenv("DEBUG", "").lower() == "true"
# ================================================


def log(msg):
    print(msg, flush=True)


def debug(msg):
    if DEBUG:
        print(f"[DEBUG] {msg}", flush=True)


def rsa_encode(pubkey_b64, string):
    """
    RSA 公钥加密。
    使用标准 base64.b64decode 转字节再 hex()，规避自定义 b64tohex 越界问题；
    明文超过单次上限时按块加密（1024 位密钥上限约 117 字节）。
    """
    pem = f"-----BEGIN PUBLIC KEY-----\n{pubkey_b64}\n-----END PUBLIC KEY-----"
    pubkey = rsa.PublicKey.load_pkcs1_openssl_pem(pem.encode())
    plaintext = string.encode()
    max_len = pubkey.n.bit_length() // 8 - 11  # PKCS#1 v1.5 需预留 11 字节
    chunks = [plaintext[i:i + max_len] for i in range(0, len(plaintext), max_len)]
    out = b"".join(rsa.encrypt(c, pubkey) for c in chunks)
    return out.hex()


def rsa_encode_with_prefix(pubkey_b64, prefix, string):
    """
    189 的 pre 前缀约定：NRP 加密时前缀为 'NRP'（去掉花括号），
    把前缀 hex 拼到密文 hex 前面。
    """
    head = (prefix or "").encode().hex()
    if head:
        return head + rsa_encode(pubkey_b64, string)
    return rsa_encode(pubkey_b64, string)


class LoginError(Exception):
    pass


def _json(r, stage):
    if r.status_code != 200:
        raise LoginError(f"{stage}：HTTP {r.status_code}")
    try:
        return r.json()
    except ValueError:
        raise LoginError(f"{stage}：响应非 JSON，前300字：{r.text[:300]}")


def login(username, password):
    if not username or not password:
        raise LoginError("账号或密码为空")
    s = requests.Session()
    s.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36",
        "Accept": "*/*",
    })
    debug("登录开始")

    # ---------- Step 1：PC 登录页（302 → unifyAccountLogin.do）----------
    r = s.get(WEB_URL + "/api/portal/unifyLoginForPC.action", params={
        "appId": APP_ID, "clientType": "10020", "returnURL": RETURN_URL,
        "timeStamp": str(int(time.time() * 1000)),
    }, timeout=TIMEOUT, allow_redirects=True)
    debug(f"Step1 状态码={r.status_code} 最终URL={r.url[:100]}")
    if r.status_code != 200:
        raise LoginError(f"登录页 HTTP {r.status_code}")
    if "unifyAccountLogin" not in r.url:
        raise LoginError(f"登录页未跳转，落点={r.url[:100]}")

    fields, patterns = {}, {
        "captchaToken": r"['\"]captchaToken['\"]\s+value=['\"]([^'\"]+)['\"]",
        "lt":           r"\blt\s*=\s*['\"]([^'\"]+)['\"]",
        "paramId":      r"\bparamId\s*=\s*['\"]([^'\"]+)['\"]",
        "reqId":        r"\breqId\s*=\s*['\"]([^'\"]+)['\"]",
    }
    for name, pat in patterns.items():
        m = re.search(pat, r.text)
        if not m:
            raise LoginError(f"登录页缺少字段[{name}]")
        fields[name] = m.group(1)
        debug(f"  {name} = {fields[name][:20]}...")

    # ---------- Step 2：加密配置 ----------
    conf = _json(s.post(AUTH_URL + "/api/logbox/config/encryptConf.do",
                        data={"appId": APP_ID}, timeout=TIMEOUT), "加密配置")
    debug(f"Step2 响应: {json.dumps(conf, ensure_ascii=False)[:400]}")

    enc = conf.get("data") if isinstance(conf.get("data"), dict) else {}
    if not enc:
        enc = conf

    debug(f"Step2 enc类型={type(enc).__name__} keys={list(enc.keys()) if isinstance(enc, dict) else 'N/A'}")

    pubkey = enc.get("pubKey")
    pre = enc.get("pre")
    debug(f"Step2 pubKey存在={'Y' if pubkey else 'N'} pre={repr(pre)[:60]}")

    if not isinstance(pubkey, str) or not pubkey:
        raise LoginError(f"pubKey 异常：type={type(pubkey).__name__}")

    try:
        eu = rsa_encode_with_prefix(pubkey, pre, username)
        ep = rsa_encode_with_prefix(pubkey, pre, password)
    except Exception as e:
        raise LoginError(f"RSA 加密失败：{type(e).__name__}: {e}")
    debug(f"Step2 eu长度={len(eu)} ep长度={len(ep)}")

    h = {"Referer": AUTH_URL + "/", "lt": fields["lt"], "REQID": fields["reqId"]}

    # ---------- Step 3：验证码检查 ----------
    rc = s.post(AUTH_URL + "/api/logbox/oauth2/needcaptcha.do", headers=h, data={
        "appKey": APP_ID, "accountType": "02", "userName": eu}, timeout=TIMEOUT)
    debug(f"Step3 状态码={rc.status_code} body={rc.text.strip()!r}")
    if rc.status_code != 200 or rc.text.strip() != "0":
        raise LoginError(f"验证码检查异常：HTTP {rc.status_code}, body={rc.text[:120]!r}")

    # ---------- Step 4：登录提交 ----------
    r4 = s.post(AUTH_URL + "/api/logbox/oauth2/loginSubmit.do", headers=h, data={
        "appKey": APP_ID, "accountType": "02", "userName": eu, "password": ep,
        "validateCode": "", "captchaToken": fields["captchaToken"], "dynamicCheck": "FALSE",
        "clientType": "1", "cb_SaveName": "3", "isOauth2": "false",
        "returnUrl": RETURN_URL, "paramId": fields["paramId"],
    }, timeout=TIMEOUT)
    debug(f"Step4 状态码={r4.status_code} 响应前400={r4.text[:400]!r}")
    d = _json(r4, "密码登录")
    debug(f"Step4 result={d.get('result')} 有toUrl={'toUrl' in d}")
    if d.get("result") not in (0, "0") or not d.get("toUrl"):
        raise LoginError(f"登录被拒绝（{d.get('result')}）：{str(d.get('msg', ''))[:120]}")

    # ---------- Step 5：换取 PC 会话（XML）----------
    r5 = s.get(API_URL + "/getSessionForPC.action", params={
        "appId": APP_ID, "clientType": "TELEPC", "version": "6.2",
        "channelId": "web_cloud.189.cn", "rand": str(int(time.time() * 1000)),
        "redirectURL": d["toUrl"],
    }, timeout=TIMEOUT, allow_redirects=True)
    debug(f"Step5 状态码={r5.status_code} 响应前200={r5.text[:200]!r}")
    m = re.search(r"<sessionKey>([^<]+)</sessionKey>", r5.text)
    if not m:
        raise LoginError(f"未取到 sessionKey，响应前300字：{r5.text[:300]}")
    s.cloud189_session_key = m.group(1)
    debug(f"Step5 sessionKey={s.cloud189_session_key[:16]}...")
    return s


def do_checkin(s):
    r = {"signin": "", "status": "failed", "error": None}
    try:
        d = _json(s.get(WEB_URL + "/mkt/userSign.action", params={
            "sessionKey": s.cloud189_session_key, "rand": str(int(time.time() * 1000)),
            "clientType": "TELEANDROID", "version": "9.0.6", "model": "KB2000",
        }, headers={"Referer": WEB_URL + "/web/main/"}, timeout=TIMEOUT), "签到")
        if "netdiskBonus" not in d or "isSign" not in d:
            raise LoginError(f"签到响应无效：{str(d)[:200]}")
        if d["isSign"] is False or d["isSign"] == "false":
            r.update(status="signed", signin=f"签到成功，获得 {d['netdiskBonus']}M 空间")
        else:
            r.update(status="already_signed", signin="今日已签到，本次未重复领取")
    except Exception as e:
        r["error"] = f"签到失败：{type(e).__name__}: {e}"
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
                    item.update(status="won", msg=f"抽中 {d.get('prizeName', '未知')}")
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
        r = requests.post(webhook, json={
            "msgtype": "text",
            "text": {"content": content},
        }, timeout=15)
        ok = r.status_code == 200 and r.json().get("errcode") == 0
        log("企业微信推送：" + ("成功" if ok else f"失败 {r.text[:100]}"))
    except Exception as e:
        log(f"企业微信推送异常：{type(e).__name__}")


def mask(u):
    return u[:3] + "***" + u[-2:] if len(u) > 5 else "***"


def main():
    start = datetime.now()
    log(f"天翼云盘签到抽奖 ｜ 启动：{start:%Y-%m-%d %H:%M:%S}")
    accounts = load_accounts()
    log(f"账户数量：{len(accounts)}")
    webhook = wecom_url(os.getenv("QYWX_KEY"))

    results, blocks = [], []
    for i, acc in enumerate(accounts, 1):
        log(f"\n账户{i} {mask(acc['username'])}")
        s, out = None, {"username": mask(acc["username"]), "signin": "", "status": "failed", "draws": []}
        try:
            s = login(acc["username"], acc["password"])
            ck = do_checkin(s)
            out.update(status=ck["status"], signin=ck["signin"] or ck["error"])
            log(f"  签到：{ck['signin'] or ck['error']}")
            draws = do_draw(s)
            out["draws"] = draws
            for j, d in enumerate(draws, 1):
                log(f"  抽奖{j} [{d['task']}]：{d['msg']}")
        except Exception as e:
            out["signin"] = f"登录失败：{type(e).__name__}: {e}"
            log(f"  {out['signin']}")
        finally:
            if s:
                s.close()
        results.append(out)
        line = [f"账户{i} {out['username']}", f"签到：{out['signin']}"]
        for j, d in enumerate(out["draws"], 1):
            line.append(f"抽奖{j} [{d['task']}]：{d['msg']}")
        blocks.append("\n".join(line))

    sc = sum(1 for r in results if r["status"] == "signed")
    al = sum(1 for r in results if r["status"] == "already_signed")
    fl = sum(1 for r in results if r["status"] == "failed")
    won = sum(1 for r in results for d in r["draws"] if d["status"] == "won")
    cost = (datetime.now() - start).total_seconds()

    header = (f"天翼云盘签到抽奖报告\n"
              f"执行时间：{start:%Y-%m-%d %H:%M:%S}\n"
              f"签到 {sc} · 已签 {al} · 失败 {fl} · 中奖 {won} · 耗时 {cost:.1f}s")
    content = header + "\n\n" + "\n\n".join(blocks)
    push_wecom(webhook, content)
    log(f"\n完成：{cost:.1f}s")


if __name__ == "__main__":
    main()
