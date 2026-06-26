import json
import os
import random
import re
import time
from datetime import datetime, timedelta
from urllib.parse import parse_qs, urlsplit
from xml.etree.ElementTree import Element, SubElement, tostring

import requests
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad

KEY = "123456".ljust(24, "0")  # 修改六位数字密码
AUTHENTICATOR = os.environ.get("AUTHENTICATOR", "")  # 用抓包得到的 Authenticator 参数

# 下面地址根据抓的包自行修改
API_EAS_IP = "10.255.75.70"
API_EAS_BASE = "http://zteepg.iptv.hk.hi.cn:8080/iptvepg/"
API_EPG_BASE = "http://10.255.79.11:8080/iptvepg/"

UDPXY_BASE = "http://192.168.1.1:5678/rtp/"
SERVICE_BASE = "http://192.168.1.1:1234"

# 如果设置了这个值，所有 HTTP 请求都会通过 rtp2httpd 的 HTTP 反代
# 例如: "http://192.168.1.1:5678" 会把 http://example.com/path 转换为 http://192.168.1.1:5678/http/example.com/path
RTP2HTTPD_HTTP_PROXY = "http://192.168.50.2:5140/app/rtp2httpd"


def proxy_url(url):
    """将 HTTP URL 转换为经过 rtp2httpd 反代的 URL"""
    if not RTP2HTTPD_HTTP_PROXY or not url.startswith("http://"):
        return url
    # 移除 http:// 前缀，构建反代 URL
    # http://example.com/path -> {RTP2HTTPD_HTTP_PROXY}/http/example.com/path
    url_without_scheme = url[7:]  # 移除 "http://"
    return f"{RTP2HTTPD_HTTP_PROXY.rstrip('/')}/http/{url_without_scheme}"


COMMON_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; ChromiumBrowser) AppleWebKit/534.24 (KHTML, like Gecko) Safari/534.24 SkWebKit-HA-CU",
}

os.chdir(os.path.dirname(__file__))


def auth_in():
    def adjust_key_parity(key_in):
        def parity_byte(key_byte):
            parity = 1
            for i in range(1, 8):
                parity ^= (key_byte >> i) & 1
            return (key_byte & 0xFE) | parity

        from Crypto.Util.py3compat import bchr, bord

        key_out = b"".join([bchr(parity_byte(bord(x))) for x in key_in])
        return key_out

    # ignore error: Triple DES key degenerates to single DES
    DES3.adjust_key_parity = adjust_key_parity

    cryptor = DES3.new(KEY, DES3.MODE_ECB)
    data = cryptor.decrypt(bytes.fromhex(AUTHENTICATOR))
    data = unpad(data, DES3.block_size).decode()
    data = data.split("$")

    # get encrypt token
    headers = COMMON_HEADERS.copy().update(
        {
            "Host": "zteepg.iptv.hk.hi.cn:8080",
        }
    )
    res = requests.get(
        proxy_url(API_EAS_BASE + "platform/getencrypttoken.jsp"),
        headers=headers,
        params={
            "UserID": data[2],
            "Action": "Login",
            "TerminalFlag": 1,
            "TerminalOsType": 0,
            "STBID": "",
            "stbtype": "",
            "skipSilentUser": 1,
        },
    ).text
    encrypt_token = re.search(r"GetAuthInfo\('(.*)'\)", res).group(1)

    # replace 8-digit random number
    data[0] = str(random.randint(0, 99999999)).zfill(8)

    # replace encrypt token
    data[1] = encrypt_token

    # auth
    session = requests.Session()
    session.headers.update(COMMON_HEADERS)
    res = session.post(
        proxy_url(API_EPG_BASE + "platform/auth.jsp"),
        params={"easip": API_EAS_IP, "ipVersion": 4, "networkid": 1},
        data={
            "UserID": data[2],
            "Authenticator": cryptor.encrypt(
                pad("$".join(data).encode(), DES3.block_size)
            )
            .hex()
            .upper(),
            "StbIP": data[4],
        },
    )
    session.cookies.set(
        "JSESSIONID", session.cookies.pop("JSESSIONID")
    )  # Remove cookie path limitation

    # convert server time to local time
    serverTime = datetime.strptime(res.headers["Date"], "%a, %d %b %Y %H:%M:%S %Z")
    serverExpiredTime = re.search(r"\('TokenExpiredTime', *'([^']*)'", res.text).group(
        1
    )
    serverExpiredTime = datetime.strptime(serverExpiredTime, "%Y.%m.%d %H:%M:%S")
    expiredTime = datetime.now() + (serverExpiredTime - serverTime)

    redirect_url = re.search(r"window\.location(?:\.href)? *= *'(.*)'", res.text).group(
        1
    )
    session.get(proxy_url(redirect_url))
    print(session.cookies.get("JSESSIONID"))

    redirect_url = urlsplit(redirect_url)
    params = {k: v[0] for k, v in parse_qs(redirect_url.query).items()}

    res = session.post(
        proxy_url(API_EPG_BASE + "function/funcportalauth.jsp"),
        data={
            "UserToken": params["UserToken"],
            "UserID": params["UserID"],
            "STBID": params["STBID"],
            "stbinfo": "",
            "prmid": "",
            "easip": params["easip"],
            "networkid": params["networkid"],
            "stbtype": "Z86",
            "drmsupplier": "",
        },
    )

    assert res.headers["X-Frame-UserToken"] == params["UserToken"]

    return session, expiredTime


_session = None
_session_expire = datetime(1970, 1, 1)

try:
    with open("iptv.json", "r") as f:
        cache = json.load(f)
        _session = requests.Session()
        _session.headers.update(COMMON_HEADERS)
        _session.cookies.update(cache["cookies"])
        _session_expire = datetime.fromisoformat(cache["expireTime"])
except FileNotFoundError:
    pass


def cached_auth_in():
    global _session, _session_expire
    if _session is None or datetime.now() >= _session_expire:
        print("[*]", "Cache expired, re-authenticating...")
        _session, _session_expire = auth_in()
        with open("iptv.json", "w") as f:
            json.dump(
                {
                    "cookies": _session.cookies.get_dict(),
                    "expireTime": _session_expire.isoformat(),
                },
                f,
            )

    return _session


def request(method, url, retry=True, **kwargs):
    global _session_expire
    session = cached_auth_in()
    res = session.request(method, proxy_url(url), **kwargs)
    err = re.search(r"qrcodeerror\.jsp\?errorcode=(\d+)", res.text)
    sessionExp = re.search(r"rebuildsessionresponse\.jsp", res.text)
    if err or sessionExp:
        if err:
            print("[!]", "An error occurred during request:", err.group(1))
        if retry:
            print("[!]", "Refreshing session...")
            _session_expire = datetime(1970, 1, 1)
            cached_auth_in()
            return request(method, url, retry=False, **kwargs)
        else:
            raise Exception("Request failed, error code: %s" % err.group(1))
    return res


def channel_list():
    res = request(
        "post",
        API_EPG_BASE + "function/frameset_builder.jsp",
        data={
            "MAIN_WIN_SRC": "/iptvepg/frame1442/portal.jsp?tempno=-1",
            "NEED_UPDATE_STB": "1",
            "BUILD_ACTION": "FRAMESET_BUILDER",
            "hdmistatus": "undefined",
        },
    )

    # parse channel info
    channels_info = re.findall(r"jsSetChannelInfo\(([^)]+)\);", res.text)
    channels_info = [
        json.loads("[%s]" % channel_info.replace("'", '"'))
        for channel_info in channels_info
    ]

    attributes = [
        "userChannelID",
        "timeShift",
        "TSTVtime",
        "isIgmp",
        "channelId",
        "channelName",
        "columnId",
        "channelType",
        "pipEnable",
        "lpvrEnable",
        "channelLevel",
        "isCanLock",
        "isIPPV",
        "mixno",
        "cdnchannelCode",
        "advertisecontent",
        "definition",
        "tvPauseEnable",
        "ottcdnchannelcode",
        "funcswitch",
        "allownettype",
    ]
    channels_info = {
        channel[4]: {k: channel[i] for i, k in enumerate(attributes)}
        for channel in channels_info
    }  #

    # parse channel config
    channels = re.findall(r"jsSetConfig\('Channel', *'([^']+)'\)", res.text)
    channels = [
        json.loads("{%s}" % re.sub(r"(,|^) *([a-zA-Z0-9]+) *=", r'\1"\2":', channel))
        for channel in channels
    ]

    # merge channel info to config
    channels = [
        {**channel, **channels_info[channel["ChannelID"]]} for channel in channels
    ]

    # 获取分类名称
    # res = request(
    #     "get", API_EPG_BASE + "frame1451/sdk_getcolumnlist.jsp?columncode=01"
    # ).json()
    # assert res["returncode"] == "0"

    # columns = {column["columncode"]: column["columnname"] for column in res["data"]}
    # channels = [
    #     {**channel, "columnname": columns[channel["columnId"]]} for channel in channels
    # ]

    with open("web/raw-response.html", "w") as f:
        f.write(res.text.strip())

    with open("web/channels.json", "w") as f:
        f.write(json.dumps(channels, indent=2, ensure_ascii=False))

    return channels


def generate_epg(channels):
    today = datetime.now()
    today_plus_3 = today + timedelta(days=3)

    tv = Element("tv")
    for channel in channels:
        channel_el = SubElement(tv, "channel", id=channel["UserChannelID"])
        SubElement(channel_el, "display-name", lang="zh").text = channel["ChannelName"]

    channel_id_map = {
        channel["ChannelID"]: channel["UserChannelID"] for channel in channels
    }

    def parse_time(time):
        return datetime.strptime(time, "%Y.%m.%d %H:%M:%S").strftime(
            "%Y%m%d%H%M%S +0800"
        )

    for i, channel in enumerate(channels):
        if i % 10 == 0:
            print("[*]", "Fetching EPG for channel", i + 1, "/", len(channels))

        # 获取节目预告
        res = request(
            "get",
            API_EPG_BASE + "/frame80/channel/ztedatajsp/prevueList.jsp?",
            params={
                "pageIndex": 1,
                "pageSize": 999,
                "isAjax": 1,
                "isJson": -1,
                "curdate": today.strftime("%Y%m%d"),
                "USERID": re.search(r"UserID=(\d+)", _session.cookies).group(1),
                "channelID": channel["ChannelID"],
                "BACKURL": "",
            },
        ).json()

        if res["returncode"] != "0":
            print("[!]", "Failed to fetch EPG for", channel["ChannelName"])
            print(res)
            continue

        for program in res["data"]:
            programme = SubElement(
                tv,
                "programme",
                start=parse_time(program["begintime"]),
                stop=parse_time(program["endtime"]),
                channel=channel_id_map[program["channelcode"]],
            )

            SubElement(programme, "title", lang="zh").text = program["prevuename"]
            SubElement(programme, "desc", lang="zh").text = program["description"]
        time.sleep(random.random())

    return (
        b'<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE tv SYSTEM "xmltv.dtd">\n'
        + tostring(tv, encoding="utf-8")
    )


def generate_m3u(channels):
    m3u = [
        '#EXTM3U url-tvg="{base}/epg.xml" x-tvg-url="{base}/epg.xml"'.format(
            base=SERVICE_BASE
        )
    ]
    for channel in channels:
        m3u_item = [
            "#EXTINF:-1",
            'tvg-id="{}"'.format(channel["UserChannelID"]),
            'tvg-name="{}"'.format(channel["ChannelName"]),
            'tvg-group="{}"'.format("未分类"),
        ]

        if os.path.exists("web/icons/{}.png".format(channel["ChannelID"])):
            m3u_item.append(
                'tvg-logo="{}/icons/{}.png"'.format(SERVICE_BASE, channel["ChannelID"])
            )

        if channel["TimeShift"] == "1":
            m3u_item.append('catchup="append"')
            m3u_item.append('catchup-source="{}"'.format(channel["TimeShiftURL"]))

        m3u.append(" ".join(m3u_item) + "," + channel["ChannelName"])
        m3u.append(re.sub(r"^igmp://", UDPXY_BASE, channel["ChannelURL"]))
    return "\n".join(m3u)


def generate_rtp2httpd_m3u(channels):
    content = ""
    # 构建组播地址到 TimeShiftURL 的映射
    multicast_to_timeshift = {}
    for channel in channels:
        if channel["ChannelSDP"]:
            # 从 ChannelURL 提取组播地址 (例如: igmp://239.253.64.120:5140 -> 239.253.64.120:5140)
            [igmp_url, rtsp_url] = channel["ChannelSDP"].split("|")
            multicast_addr = igmp_url.replace("igmp://", "")
            multicast_to_timeshift[multicast_addr] = (
                rtsp_url,
                channel.get("TimeShiftLength", "3600"),
            )

    print(f"[*] Built timeshift mapping for {len(multicast_to_timeshift)} channels")

    # 抓取远程 M3U 文件
    try:
        m3u_url = "https://gist.githubusercontent.com/stackia/9dba21f67df6cd3226d4776960ee289b/raw/"
        m3u_response = requests.get(m3u_url, timeout=10)
        m3u_response.raise_for_status()
        m3u_content = m3u_response.text

        # 处理 M3U 内容
        lines = m3u_content.split("\n")
        processed_lines = []
        current_extinf = None

        matched_count = 0
        for line in lines:
            # 检查是否是 #EXTINF 行
            if line.startswith("#EXTINF"):
                current_extinf = line
                # 不要立即添加，等待处理下一行
            elif line.startswith("rtp://") and current_extinf:
                # 从 rtp 地址提取组播地址
                # 例如: rtp://239.253.64.120:5140/?fcc=... -> 239.253.64.120:5140
                match = re.match(r"rtp://([^/?]+)", line)
                if match:
                    multicast_addr = match.group(1)
                    # 查找对应的 TimeShiftURL
                    if multicast_addr in multicast_to_timeshift:
                        timeshift_url, timeshift_length = multicast_to_timeshift[
                            multicast_addr
                        ]
                        # 添加 catchup 参数
                        catchup_source = (
                            f"{timeshift_url}&playseek={{utc:YmdHMS}}-{{utcend:YmdHMS}}"
                        )
                        if int(timeshift_length) > 0:
                            catchup_source += (
                                f"&r2h-seek-mode=range({timeshift_length})"
                            )
                        # 在逗号之前插入 catchup 属性
                        # 格式: #EXTINF:-1 ... group-title="央视",CCTV-1
                        # 需要变成: #EXTINF:-1 ... group-title="央视" catchup="default" catchup-source="...",CCTV-1
                        last_comma = current_extinf.rfind(",")
                        if last_comma != -1:
                            current_extinf = (
                                current_extinf[:last_comma]
                                + f' catchup="default" catchup-source="{catchup_source}"'
                                + current_extinf[last_comma:]
                            )
                        matched_count += 1

                # 添加处理后的 #EXTINF 行和当前 rtp 行
                processed_lines.append(current_extinf)
                processed_lines.append(line)
                current_extinf = None
            else:
                # 如果不是 rtp 行，但之前有 #EXTINF，先添加它
                if current_extinf:
                    processed_lines.append(current_extinf)
                    current_extinf = None

                processed_lines.append(line)

        print(f"[*] Added catchup to {matched_count} channels")

        # 将处理后的 M3U 内容添加到 [services] 后面
        content += "\n".join(processed_lines)
        content += "\n"

    except Exception as e:
        print(f"[!] Failed to fetch or process M3U file: {e}")

    return content


if __name__ == "__main__":
    channels = channel_list()

    # with open("web/epg.xml", "wb") as f:
    #     f.write(generate_epg(channels))

    # with open("web/iptv.m3u", "w") as f:
    #     f.write(generate_m3u(channels))

    with open("web/hainan-telecom-iptv.m3u", "w") as f:
        f.write(generate_rtp2httpd_m3u(channels))

    print("[*]", "Done")
