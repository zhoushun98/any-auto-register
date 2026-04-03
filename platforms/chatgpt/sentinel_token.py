"""
Sentinel Token 生成器模块
基于对 sentinel.openai.com SDK 的逆向分析
"""

import base64
import json
import os
import random
import subprocess
import tempfile
import time
import uuid
from pathlib import Path
from shutil import which
from urllib.request import Request, urlopen


SENTINEL_REQ_URL = "https://sentinel.openai.com/backend-api/sentinel/req"
SENTINEL_SDK_VERSION = os.getenv("OPENAI_SENTINEL_SDK_VERSION", "20260219f9f6")
SENTINEL_SDK_URL = f"https://sentinel.openai.com/sentinel/{SENTINEL_SDK_VERSION}/sdk.js"
SENTINEL_REFERER = (
    f"https://sentinel.openai.com/backend-api/sentinel/frame.html?sv={SENTINEL_SDK_VERSION}"
)


def _resolve_vm_script() -> Path | None:
    direct_script = os.getenv("OPENAI_SENTINEL_VM_SCRIPT", "").strip()
    if direct_script:
        path = Path(direct_script).expanduser().resolve()
        if path.exists() and path.is_file():
            return path

    vm_dir = os.getenv("OPENAI_SENTINEL_VM_DIR", "").strip()
    if vm_dir:
        candidate = Path(vm_dir).expanduser().resolve() / "openai_sentinel_vm.js"
        if candidate.exists() and candidate.is_file():
            return candidate

    # 默认尝试工作区同级目录：D:/Develop/AI/sentinel/openai_sentinel_vm.js
    candidate = (
        Path(__file__).resolve().parents[3] / "sentinel" / "openai_sentinel_vm.js"
    )
    if candidate.exists() and candidate.is_file():
        return candidate
    return None


def _resolve_node_binary() -> str | None:
    node_env = os.getenv("OPENAI_SENTINEL_NODE_PATH", "").strip()
    if node_env:
        path = Path(node_env).expanduser().resolve()
        if path.exists() and path.is_file():
            return str(path)
    return which("node")


def _ensure_sdk_file() -> Path | None:
    direct = os.getenv("OPENAI_SENTINEL_SDK_FILE", "").strip()
    if direct:
        path = Path(direct).expanduser().resolve()
        if path.exists() and path.is_file():
            return path

    cache_dir = Path(tempfile.gettempdir()) / "openai-sentinel-cache" / SENTINEL_SDK_VERSION
    cache_file = cache_dir / "sdk.js"
    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
    except Exception:
        return None
    if cache_file.exists() and cache_file.stat().st_size > 0:
        return cache_file

    request = Request(
        SENTINEL_SDK_URL,
        headers={
            "User-Agent": "Mozilla/5.0",
            "Referer": "https://auth.openai.com/",
            "Accept": "*/*",
        },
    )
    try:
        with urlopen(request, timeout=20) as response:
            cache_file.write_bytes(response.read())
    except Exception:
        return None

    if cache_file.exists() and cache_file.stat().st_size > 0:
        return cache_file
    return None


def _vm_browser_payload(device_id: str, user_agent: str | None) -> dict:
    return {
        "device_id": str(device_id or "").strip(),
        "user_agent": user_agent
        or (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/146.0.0.0 Safari/537.36"
        ),
        "language": "zh-CN",
        "languages": ["zh-CN", "zh"],
        "hardware_concurrency": 12,
        "screen_width": 1366,
        "screen_height": 768,
        "performance_now": 12345.67,
        "time_origin": 1710000000000.0,
        "js_heap_size_limit": 4294967296,
    }


def _run_vm(action: str, payload: dict) -> dict | None:
    node_binary = _resolve_node_binary()
    vm_script = _resolve_vm_script()
    sdk_file = _ensure_sdk_file()
    if not node_binary or not vm_script or not sdk_file:
        return None

    full_payload = {"action": action, "sdk_path": str(sdk_file), **(payload or {})}
    timeout_sec = int(os.getenv("OPENAI_SENTINEL_VM_TIMEOUT_SEC", "40") or "40")

    try:
        process = subprocess.run(
            [node_binary, str(vm_script)],
            input=json.dumps(full_payload, separators=(",", ":")),
            text=True,
            capture_output=True,
            cwd=str(vm_script.parent),
            timeout=max(5, timeout_sec),
            check=False,
        )
    except Exception:
        return None

    if process.returncode != 0:
        return None
    output = str(process.stdout or "").strip()
    if not output:
        return None
    try:
        data = json.loads(output)
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def _build_sentinel_token_via_vm(
    session,
    device_id,
    *,
    flow="authorize_continue",
    user_agent=None,
    sec_ch_ua=None,
    impersonate=None,
):
    payload = _vm_browser_payload(str(device_id or ""), user_agent)
    req_data = _run_vm("requirements", payload)
    request_p = str((req_data or {}).get("request_p") or "").strip()
    if not request_p:
        return None

    challenge = fetch_sentinel_challenge(
        session,
        device_id,
        flow=flow,
        user_agent=user_agent,
        sec_ch_ua=sec_ch_ua,
        impersonate=impersonate,
        request_p=request_p,
    )
    if not challenge:
        return None
    c_value = str(challenge.get("token") or "").strip()
    if not c_value:
        return None

    solved = _run_vm(
        "solve",
        {**payload, "request_p": request_p, "challenge": challenge},
    )
    final_p = str((solved or {}).get("final_p") or (solved or {}).get("p") or "").strip()
    if not final_p:
        return None
    t_value = (solved or {}).get("t")

    return json.dumps(
        {
            "p": final_p,
            "t": "" if t_value is None else str(t_value),
            "c": c_value,
            "id": device_id,
            "flow": flow,
        },
        separators=(",", ":"),
    )


class SentinelTokenGenerator:
    """
    Sentinel Token 纯 Python 生成器
    
    通过逆向 sentinel SDK 的 PoW 算法，纯 Python 构造合法的 openai-sentinel-token。
    """

    MAX_ATTEMPTS = 500000  # 最大 PoW 尝试次数
    ERROR_PREFIX = "wQ8Lk5FbGpA2NcR9dShT6gYjU7VxZ4D"  # SDK 中的错误前缀常量

    def __init__(self, device_id=None, user_agent=None):
        self.device_id = device_id or str(uuid.uuid4())
        self.user_agent = user_agent or (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/145.0.0.0 Safari/537.36"
        )
        self.requirements_seed = str(random.random())
        self.sid = str(uuid.uuid4())

    @staticmethod
    def _fnv1a_32(text):
        """
        FNV-1a 32位哈希算法（从 SDK JS 逆向还原）
        """
        h = 2166136261  # FNV offset basis
        for ch in text:
            code = ord(ch)
            h ^= code
            h = (h * 16777619) & 0xFFFFFFFF

        # xorshift 混合（murmurhash3 finalizer）
        h ^= h >> 16
        h = (h * 2246822507) & 0xFFFFFFFF
        h ^= h >> 13
        h = (h * 3266489909) & 0xFFFFFFFF
        h ^= h >> 16
        h = h & 0xFFFFFFFF

        return format(h, "08x")

    def _get_config(self):
        """构造浏览器环境数据数组"""
        from datetime import datetime, timezone
        
        screen_info = "1920x1080"
        now = datetime.now(timezone.utc)
        date_str = now.strftime("%a %b %d %Y %H:%M:%S GMT+0000 (Coordinated Universal Time)")
        js_heap_limit = 4294705152
        nav_random1 = random.random()
        ua = self.user_agent
        script_src = "https://sentinel.openai.com/sentinel/20260124ceb8/sdk.js"
        script_version = None
        data_build = None
        language = "en-US"
        languages = "en-US,en"
        nav_random2 = random.random()
        
        nav_props = [
            "vendorSub", "productSub", "vendor", "maxTouchPoints",
            "scheduling", "userActivation", "doNotTrack", "geolocation",
            "connection", "plugins", "mimeTypes", "pdfViewerEnabled",
            "webkitTemporaryStorage", "webkitPersistentStorage",
            "hardwareConcurrency", "cookieEnabled", "credentials",
            "mediaDevices", "permissions", "locks", "ink",
        ]
        nav_prop = random.choice(nav_props)
        nav_val = f"{nav_prop}−undefined"
        
        doc_key = random.choice(["location", "implementation", "URL", "documentURI", "compatMode"])
        win_key = random.choice(["Object", "Function", "Array", "Number", "parseFloat", "undefined"])
        perf_now = random.uniform(1000, 50000)
        hardware_concurrency = random.choice([4, 8, 12, 16])
        time_origin = time.time() * 1000 - perf_now

        config = [
            screen_info, date_str, js_heap_limit, nav_random1, ua,
            script_src, script_version, data_build, language, languages,
            nav_random2, nav_val, doc_key, win_key, perf_now,
            self.sid, "", hardware_concurrency, time_origin,
        ]
        return config

    @staticmethod
    def _base64_encode(data):
        """模拟 SDK 的 E() 函数：JSON.stringify → TextEncoder.encode → btoa"""
        json_str = json.dumps(data, separators=(",", ":"), ensure_ascii=False)
        encoded = json_str.encode("utf-8")
        return base64.b64encode(encoded).decode("ascii")

    def _run_check(self, start_time, seed, difficulty, config, nonce):
        """单次 PoW 检查"""
        config[3] = nonce
        config[9] = round((time.time() - start_time) * 1000)
        data = self._base64_encode(config)
        hash_input = seed + data
        hash_hex = self._fnv1a_32(hash_input)
        diff_len = len(difficulty)
        if hash_hex[:diff_len] <= difficulty:
            return data + "~S"
        return None

    def generate_token(self, seed=None, difficulty=None):
        """生成 sentinel token（完整 PoW 流程）"""
        if seed is None:
            seed = self.requirements_seed
            difficulty = difficulty or "0"

        start_time = time.time()
        config = self._get_config()

        for i in range(self.MAX_ATTEMPTS):
            result = self._run_check(start_time, seed, difficulty, config, i)
            if result:
                return "gAAAAAB" + result

        return "gAAAAAB" + self.ERROR_PREFIX + self._base64_encode(str(None))

    def generate_requirements_token(self):
        """生成 requirements token（不需要服务端参数）"""
        config = self._get_config()
        config[3] = 1
        config[9] = round(random.uniform(5, 50))
        data = self._base64_encode(config)
        return "gAAAAAC" + data


def fetch_sentinel_challenge(
    session,
    device_id,
    flow="authorize_continue",
    user_agent=None,
    sec_ch_ua=None,
    impersonate=None,
    request_p=None,
):
    """调用 sentinel 后端 API 获取 challenge 数据"""
    generator = SentinelTokenGenerator(device_id=device_id, user_agent=user_agent)
    request_p = str(request_p or "").strip() or generator.generate_requirements_token()
    req_body = {
        "p": request_p,
        "id": device_id,
        "flow": flow,
    }
    
    headers = {
        "Content-Type": "text/plain;charset=UTF-8",
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Referer": SENTINEL_REFERER,
        "Origin": "https://sentinel.openai.com",
        "User-Agent": user_agent or "Mozilla/5.0",
        "sec-ch-ua": sec_ch_ua or '"Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
    }

    kwargs = {
        "data": json.dumps(req_body),
        "headers": headers,
        "timeout": 20,
    }
    if impersonate:
        kwargs["impersonate"] = impersonate

    try:
        resp = session.post(SENTINEL_REQ_URL, **kwargs)
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    
    return None


def build_sentinel_token(session, device_id, flow="authorize_continue", user_agent=None, sec_ch_ua=None, impersonate=None):
    """构建完整的 openai-sentinel-token JSON 字符串"""
    vm_token = _build_sentinel_token_via_vm(
        session,
        device_id,
        flow=flow,
        user_agent=user_agent,
        sec_ch_ua=sec_ch_ua,
        impersonate=impersonate,
    )
    if vm_token:
        return vm_token

    challenge = fetch_sentinel_challenge(
        session,
        device_id,
        flow=flow,
        user_agent=user_agent,
        sec_ch_ua=sec_ch_ua,
        impersonate=impersonate,
    )
    
    if not challenge:
        return None

    c_value = challenge.get("token", "")
    if not c_value:
        return None

    pow_data = challenge.get("proofofwork") or {}
    generator = SentinelTokenGenerator(device_id=device_id, user_agent=user_agent)

    if pow_data.get("required") and pow_data.get("seed"):
        p_value = generator.generate_token(
            seed=pow_data.get("seed"),
            difficulty=pow_data.get("difficulty", "0"),
        )
    else:
        p_value = generator.generate_requirements_token()

    return json.dumps({
        "p": p_value,
        "t": "",
        "c": c_value,
        "id": device_id,
        "flow": flow,
    }, separators=(",", ":"))


def build_sentinel_token_vm_only(
    session,
    device_id,
    flow="authorize_continue",
    user_agent=None,
    sec_ch_ua=None,
    impersonate=None,
):
    """仅使用 VM 链路生成 sentinel token（不回退 PoW）。"""
    return _build_sentinel_token_via_vm(
        session,
        device_id,
        flow=flow,
        user_agent=user_agent,
        sec_ch_ua=sec_ch_ua,
        impersonate=impersonate,
    )
