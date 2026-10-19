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
ACCOUNT_TYPE = "01"   # ★ 关键：PC 登录入口用 01
DEBUG = os.getenv("DEBUG", "").lower() == "true"
# ================================================


def log(msg):
    print(msg, flush=True)


def debug(msg):
    if DEBUG:
        print(f"[DEBUG] {msg}", flush=True)


def rsa_encrypt_raw(pubkey_b64, plaintext):
    pem = f"-----BEGIN PUBLIC KEY-----\n{pubkey_b64}\n-----END PUBLIC KEY-----"
    pubkey = rsa.PublicKey.load_pkcs1_openssl_pem(pem.encode())
    max_len = pubkey.n.bit_length() // 8 - 11
    chunks = [plaintext[i:i + max_len] for i in range(0, len(plaintext), max_len)]
    return b"".join(rsa.encrypt(c, pubkey) for c in chunks)


def encode_for_login(pubkey_b64, pre, value):
    head = (pre or "").encode().hex()
    b64 = base64.urlsafe_b64encode(value.encode()).rstrip(b"=").decode()
    cipher = rsa_encrypt_raw(pubkey_b64, b64.encode())
    return head + cipher.hex()


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
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/87.0.4280.88 Safari/537.36"
        ),
        "Accept": "*/*",
    })

    debug("登录开始")

    try:
        # Step 1：先获取 RSA 公钥和 pre
        conf = _json(
            s.post(
                AUTH_URL + "/api/logbox/config/encryptConf.do",
                timeout=TIMEOUT,
            ),
            "获取加密配置",
        )

        enc = conf.get("data")
        if not isinstance(enc, dict):
            enc = conf

        pubkey = enc.get("pubKey")
        pre = enc.get("pre", "")

        if not isinstance(pubkey, str) or not pubkey:
            raise LoginError("加密配置未返回有效 pubKey")

        if not isinstance(pre, str):
            raise LoginError("加密配置中的 pre 格式异常")

        debug(f"Step1 公钥获取成功，pre={pre!r}")

        # Step 2：获取登录页面动态参数
        page = s.get(
            WEB_URL + "/api/portal/unifyLoginForPC.action",
            params={
                "appId": APP_ID,
                "clientType": "10020",
                "returnURL": RETURN_URL,
                "timeStamp": str(int(time.time() * 1000)),
            },
            timeout=TIMEOUT,
            allow_redirects=True,
        )

        debug(
            f"Step2 状态码={page.status_code} "
            f"登录页参数解析开始"
        )

        if page.status_code != 200:
            raise LoginError(f"登录页面 HTTP {page.status_code}")

        patterns = {
            "captchaToken": [
                r"""['"]captchaToken['"]\s+value=['"]([^'"]+)['"]""",
                r"""name=['"]captchaToken['"][^>]*value=['"]([^'"]+)['"]""",
            ],
            "lt": [
                r"""\blt\s*=\s*['"]([^'"]+)['"]""",
            ],
            "paramId": [
                r"""\bparamId\s*=\s*['"]([^'"]+)['"]""",
            ],
            "reqId": [
                r"""\breqId\s*=\s*['"]([^'"]+)['"]""",
            ],
        }

        fields = {}
        for name, candidates in patterns.items():
            for pattern in candidates:
                match = re.search(pattern, page.text, re.S)
                if match:
                    fields[name] = match.group(1)
                    break

            if name not in fields:
                raise LoginError(f"登录页面缺少动态参数：{name}")

        debug("Step2 captchaToken/lt/paramId/reqId 获取成功")

        # Step 3：按参考代码加密原始账号和密码
        # 不做 Base64，不将 pre 转成 hex
        pem = (
            "-----BEGIN PUBLIC KEY-----\n"
            + pubkey
            + "\n-----END PUBLIC KEY-----"
        )
        public_key = rsa.PublicKey.load_pkcs1_openssl_pem(
            pem.encode("ascii")
        )

        username_cipher = rsa.encrypt(
            username.strip().encode("utf-8"),
            public_key,
        ).hex()

        password_cipher = rsa.encrypt(
            password.encode("utf-8"),
            public_key,
        ).hex()

        encrypted_username = pre + username_cipher
        encrypted_password = pre + password_cipher

        debug(
            f"Step3 加密完成："
            f"账号密文长度={len(encrypted_username)}，"
            f"密码密文长度={len(encrypted_password)}"
        )

        # Step 4：提交登录
        # 与上传的旧版参考代码保持一致，AccountType 使用 02
        headers = {
            "Referer": AUTH_URL + "/",
            "Origin": AUTH_URL,
            "lt": fields["lt"],
            "REQID": fields["reqId"],
            "Accept": "application/json;charset=UTF-8",
        }

        login_data = {
            "appKey": APP_ID,
            "accountType": "02",
            "validateCode": "",
            "captchaToken": fields["captchaToken"],
            "dynamicCheck": "FALSE",
            "clientType": "1",
            "cb_SaveName": "3",
            "isOauth2": "false",
            "returnUrl": RETURN_URL,
            "paramId": fields["paramId"],
            "userName": encrypted_username,
            "password": encrypted_password,
        }

        response = s.post(
            AUTH_URL + "/api/logbox/oauth2/loginSubmit.do",
            headers=headers,
            data=login_data,
            timeout=TIMEOUT,
        )

        debug(f"Step4 状态码={response.status_code}")

        login_result = _json(response, "提交登录")
        result_code = login_result.get("result")
        message = str(login_result.get("msg", ""))

        debug(
            f"Step4 result={result_code}, "
            f"msg={message[:100]!r}"
        )

        if str(result_code) != "0":
            raise LoginError(
                f"登录被拒绝（{result_code}）：{message[:120]}"
            )

        redirect_url = login_result.get("toUrl")
        if not redirect_url:
            raise LoginError("登录返回成功，但缺少 toUrl")

        # Step 5：获取云盘 session
        session_response = s.get(
            API_URL + "/getSessionForPC.action",
            params={
                "appId": APP_ID,
                "clientType": "TELEPC",
                "version": "6.2",
                "channelId": "web_cloud.189.cn",
                "rand": str(int(time.time() * 1000)),
                "redirectURL": redirect_url,
            },
            timeout=TIMEOUT,
            allow_redirects=True,
        )

        debug(
            f"Step5 状态码={session_response.status_code}"
        )

        if session_response.status_code != 200:
            raise LoginError(
                f"获取 session HTTP {session_response.status_code}"
            )

        session_key = ""

        # 兼容 JSON 响应
        try:
            session_json = session_response.json()
            session_key = (
                session_json.get("sessionKey", "")
                or session_json.get("data", {}).get("sessionKey", "")
                if isinstance(session_json, dict)
                else ""
            )
        except (ValueError, TypeError):
            pass

        # 兼容 XML 响应
        if not session_key:
            match = re.search(
                r"<sessionKey>([^<]+)</sessionKey>",
                session_response.text,
            )
            if match:
                session_key = match.group(1)

        if not session_key:
            raise LoginError(
                "登录提交成功，但响应中未找到 sessionKey"
            )

        s.cloud189_session_key = session_key
        debug("Step5 获取 sessionKey 成功")
        return s

    except Exception:
        s.close()
        raise




def do_checkin(s):
    r = {"signin": "", "status": "failed", "error": None}

    url = WEB_URL + "/mkt/userSign.action"
    params = {
        "sessionKey": s.cloud189_session_key,
        "rand": str(int(time.time() * 1000)),
        "clientType": "TELEANDROID",
        "version": "9.0.6",
        "model": "KB2000",
    }
    headers = {
        "Referer": WEB_URL + "/web/main/",
        "Connection": "close",
    }

    # 最多尝试 3 次，只对网络连接异常进行重试
    for attempt in range(1, 4):
        try:
            response = s.get(
                url,
                params=params,
                headers=headers,
                timeout=TIMEOUT,
            )

            d = _json(response, "签到")

            if "netdiskBonus" not in d or "isSign" not in d:
                raise LoginError(
                    f"签到响应无效：{str(d)[:200]}"
                )

            if d["isSign"] is False or d["isSign"] == "false":
                r.update(
                    status="signed",
                    signin=f"签到成功，获得 {d['netdiskBonus']}M 空间",
                )
            else:
                r.update(
                    status="already_signed",
                    signin="今日已签到，本次未重复领取",
                )

            return r

        except (
            requests.exceptions.ConnectionError,
            requests.exceptions.Timeout,
        ) as e:
            debug(
                f"签到网络异常，第 {attempt}/3 次："
                f"{type(e).__name__}: {e}"
            )

            if attempt < 3:
                time.sleep(attempt * 2)
            else:
                r["error"] = (
                    f"签到失败：连续 3 次网络请求异常，"
                    f"{type(e).__name__}: {e}"
                )
                return r

        except Exception as e:
            r["error"] = f"签到失败：{type(e).__name__}: {e}"
            return r

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
