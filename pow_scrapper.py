from curl_cffi import requests
import re

def grab_tokens():
    session = requests.Session(impersonate="chrome124")
    response = session.get(f"https://guns.lol/hris", timeout=15)
    response.raise_for_status()

    html = response.text
    match = re.compile(r"const\s+_gs_sets\s*=\s*\{([^}]*)\}", re.DOTALL).search(html)
    if not match:
        raise RuntimeError("_gs_sets not found / CF challenge or layout change")
    body = match.group(1)

    values = {}
    for match in re.compile(r"""([_A-Za-z][_A-Za-z0-9]*)\s*:\s*(?:'([^']*)'|"([^"]*)")""").finditer(body):
        key = match.group(1)
        val = match.group(2) if match.group(2) is not None else match.group(3)
        values[key] = val

    return {
        "o09": values["o09"],
        "_n": values["_n"],
        "_org_ts": values["_org_ts"],
        "_2xa": values["_2xa"],
    }
