#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import asyncio
import fcntl
import ipaddress
import json
import logging
import os
import re
import socket
import subprocess
import time
import uuid
from typing import Dict, List, Optional

import requests
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes, MessageHandler, filters

APP_DIR = '/opt/ip-analyzer-pro'
CONFIG_FILE = f'{APP_DIR}/config.json'
ITDOG_URL = 'https://www.itdog.cn/ping/'
BROWSER_TIMEOUT = 120
ITDOG_WAIT_SECONDS = 35
TG_MSG_LIMIT = 3800

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

DEFAULT_CONFIG = {
    'telegram': {
        'bot_token': '',
        'admin_id': ''
    },
    'itdog_wait_seconds': ITDOG_WAIT_SECONDS,
    'only_admin': False
}

DNSBL_ZONES = [
    ('Spamhaus', 'zen.spamhaus.org'),
    ('Spamcop', 'bl.spamcop.net'),
    ('Barracuda', 'b.barracudacentral.org'),
]

TARGET_PROVINCES = ('广东', '广西')
TARGET_ISP_RULES = {
    '电信': ('电信', 'Telecom', 'CHINANET'),
    '联通': ('联通', 'Unicom', 'CUCC'),
    '移动': ('移动', 'CMCC', 'Mobile'),
}
OVERSEAS_TARGETS = {
    '美国': ('美国', 'united states', 'usa', ' los angeles', ' seattle', ' dallas', ' silicon valley', ' ashburn'),
    '日本': ('日本', 'japan', ' tokyo', ' osaka'),
    '新加坡': ('新加坡', 'singapore'),
    '德国': ('德国', 'germany', ' frankfurt'),
}
T1_ASN_MAP = {
    3320: 'DTAG (Deutsche Telekom)',
    12956: 'Telxius',
    6453: 'TATA Communications',
    3491: 'PCCW Global',
    1299: 'Arelion (Telia Carrier)',
    6762: 'Sparkle (Telecom Italia)',
    3257: 'GTT',
    3356: 'Lumen (Level 3)',
    7018: 'AT&T',
}
ASN_PROFILE_CACHE: Dict[int, Dict] = {}


def load_config() -> dict:
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return DEFAULT_CONFIG.copy()


def save_config(config: dict) -> None:
    os.makedirs(APP_DIR, exist_ok=True)
    with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
        json.dump(config, f, ensure_ascii=False, indent=2)


def is_valid_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def parse_ips(text: str) -> List[str]:
    candidates = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[0-9a-fA-F:]{2,}\b', text)
    result = []
    for item in candidates:
        if is_valid_ip(item) and item not in result:
            result.append(item)
    return result


def chunk_text(text: str, limit: int = TG_MSG_LIMIT) -> List[str]:
    if len(text) <= limit:
        return [text]
    chunks = []
    current = ''
    for line in text.splitlines(True):
        if len(current) + len(line) > limit:
            if current:
                chunks.append(current)
            current = line
        else:
            current += line
    if current:
        chunks.append(current)
    return chunks


def run_cmd(cmd: List[str], timeout: int = 60, cwd: Optional[str] = None) -> str:
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd)
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or proc.stdout or '').strip() or 'command failed')
    return proc.stdout.strip()


def browser_eval(session: str, script: str, timeout: int = 60) -> str:
    """Run JS via /usr/local/bin/agent-browser eval --stdin, return stdout."""
    proc = subprocess.run(
        ['/usr/local/bin/agent-browser', '--session-name', session, 'eval', '--stdin'],
        input=script,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    out = (proc.stdout or '').strip()
    if proc.returncode != 0:
        err = (proc.stderr or '').strip()
        raise RuntimeError(err or f'eval failed (rc={proc.returncode})')
    return out


def safe_json_loads(raw: str):
    raw = raw.strip()
    try:
        value = json.loads(raw)
        if isinstance(value, str):
            return json.loads(value)
        return value
    except Exception:
        start = raw.find('{')
        end = raw.rfind('}')
        if start != -1 and end != -1 and end > start:
            return json.loads(raw[start:end + 1])
        start = raw.find('[')
        end = raw.rfind(']')
        if start != -1 and end != -1 and end > start:
            return json.loads(raw[start:end + 1])
        raise


def query_ip_meta(ip: str) -> Dict:
    meta = {
        'ip': ip,
        'asn': '未知',
        'holder': '未知',
        'country': '未知',
        'org': '未知',
        'route': '未知',
    }

    try:
        resp = requests.get(
            f'https://stat.ripe.net/data/network-info/data.json?resource={ip}',
            timeout=15,
            headers={'User-Agent': 'Mozilla/5.0'}
        )
        data = resp.json().get('data', {})
        asns = data.get('asns') or []
        prefix = data.get('prefix')
        if asns:
            meta['asn'] = 'AS' + str(asns[0])
        if prefix:
            meta['route'] = prefix
    except Exception as e:
        logger.warning('RIPE network-info failed: %s', e)

    try:
        resp = requests.get(
            f'https://stat.ripe.net/data/whois/data.json?resource={ip}',
            timeout=15,
            headers={'User-Agent': 'Mozilla/5.0'}
        )
        records = resp.json().get('data', {}).get('records', [])
        for group in records:
            for item in group:
                key = str(item.get('key', '')).lower()
                value = item.get('value', '')
                if key in ('origin', 'originas') and meta['asn'] == '未知':
                    if not str(value).upper().startswith('AS'):
                        meta['asn'] = 'AS' + str(value)
                    else:
                        meta['asn'] = str(value)
                if key in ('descr', 'netname', 'org-name', 'organisation', 'org') and meta['holder'] == '未知':
                    meta['holder'] = str(value)
    except Exception as e:
        logger.warning('RIPE whois failed: %s', e)

    try:
        resp = requests.get(
            f'http://ip-api.com/json/{ip}?fields=status,country,isp,org,as,asname,query',
            timeout=15,
            headers={'User-Agent': 'Mozilla/5.0'}
        )
        data = resp.json()
        if data.get('status') == 'success':
            meta['country'] = data.get('country') or meta['country']
            meta['org'] = data.get('org') or data.get('isp') or meta['org']
            if meta['holder'] == '未知':
                meta['holder'] = data.get('asname') or data.get('org') or data.get('isp') or meta['holder']
            if meta['asn'] == '未知' and data.get('as'):
                m = re.search(r'(AS\d+)', data.get('as', ''))
                if m:
                    meta['asn'] = m.group(1)
    except Exception as e:
        logger.warning('ip-api failed: %s', e)

    return meta


def check_dnsbl(ip: str) -> Dict:
    result = {'listed': [], 'status': '未命中公开 DNSBL'}
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.version != 4:
            result['status'] = 'IPv6 暂不做 DNSBL 纯净度检查'
            return result
        reverse_ip = '.'.join(reversed(ip.split('.')))
        for name, zone in DNSBL_ZONES:
            query = f'{reverse_ip}.{zone}'
            try:
                socket.gethostbyname(query)
                result['listed'].append(name)
            except socket.gaierror:
                pass
            except Exception:
                pass
        if result['listed']:
            result['status'] = '命中: ' + ', '.join(result['listed'])
        return result
    except Exception as e:
        return {'listed': [], 'status': f'检查失败: {e}'}


def _parse_asn_int(asn_value: str) -> Optional[int]:
    m = re.search(r'(\d+)', str(asn_value or ''))
    return int(m.group(1)) if m else None


def detect_focus_group(node: str) -> Optional[str]:
    if not any(p in node for p in TARGET_PROVINCES):
        return None
    province = next((p for p in TARGET_PROVINCES if p in node), None)
    if not province:
        return None
    for isp, keys in TARGET_ISP_RULES.items():
        if any(k in node for k in keys):
            return f'{province}{isp}'
    return None


def summarize_focus_rows(rows: List[Dict]) -> List[Dict]:
    grouped = {}
    for row in rows:
        node = row.get('node', '')
        group = detect_focus_group(node)
        if not group:
            continue
        ms = parse_ms(row.get('average', ''))
        loss = parse_percent(row.get('loss', ''))
        bucket = grouped.setdefault(group, [])
        bucket.append({'row': row, 'ms': ms if ms is not None else 99999.0, 'loss': loss if loss is not None else 0.0})

    results = []
    for group in sorted(grouped.keys()):
        items = grouped[group]
        best = min(items, key=lambda x: (x['loss'], x['ms']))
        ms_values = [x['ms'] for x in items if x['ms'] < 99999]
        loss_values = [x['loss'] for x in items]
        results.append({
            'group': group,
            'nodes': len(items),
            'best_node': best['row'].get('node', '未知节点'),
            'best_avg': best['row'].get('average', '--'),
            'best_loss': best['row'].get('loss', '--'),
            'avg_ms': round(sum(ms_values) / len(ms_values), 1) if ms_values else None,
            'avg_loss': round(sum(loss_values) / len(loss_values), 2) if loss_values else None,
        })
    return results


def detect_overseas_group(row: Dict) -> Optional[str]:
    node = str(row.get('node', '') or '')
    loc = str(row.get('ip_location', '') or '')
    text = f'{node} {loc}'.lower()
    for country, keys in OVERSEAS_TARGETS.items():
        if any(k in text for k in keys):
            return country
    return None


def summarize_overseas_rows(rows: List[Dict]) -> List[Dict]:
    grouped = {}
    for row in rows:
        group = detect_overseas_group(row)
        if not group:
            continue
        ms = parse_ms(row.get('average', ''))
        loss = parse_percent(row.get('loss', ''))
        bucket = grouped.setdefault(group, [])
        bucket.append({'row': row, 'ms': ms if ms is not None else 99999.0, 'loss': loss if loss is not None else 100.0})

    results = []
    for country in ('美国', '日本', '新加坡', '德国'):
        items = grouped.get(country, [])
        if not items:
            continue
        best = min(items, key=lambda x: (x['loss'], x['ms']))
        ms_values = [x['ms'] for x in items if x['ms'] < 99999]
        loss_values = [x['loss'] for x in items]
        results.append({
            'group': country,
            'nodes': len(items),
            'best_node': best['row'].get('node', '未知节点'),
            'best_avg': best['row'].get('average', '--'),
            'best_loss': best['row'].get('loss', '--'),
            'avg_ms': round(sum(ms_values) / len(ms_values), 1) if ms_values else None,
            'avg_loss': round(sum(loss_values) / len(loss_values), 2) if loss_values else None,
        })
    return results


def _extract_country_from_asn(asn: int, cache: Dict[int, str]) -> str:
    if asn in cache:
        return cache[asn]
    if asn in ASN_PROFILE_CACHE and isinstance(ASN_PROFILE_CACHE[asn], dict):
        cached_country = ASN_PROFILE_CACHE[asn].get('country')
        if cached_country:
            cache[asn] = cached_country
            return cached_country

    country = '未知'
    try:
        resp = requests.get(
            f'https://stat.ripe.net/data/whois/data.json?resource=AS{asn}',
            timeout=6,
            headers={'User-Agent': 'Mozilla/5.0'}
        )
        records = resp.json().get('data', {}).get('records', [])
        for group in records:
            for item in group:
                if str(item.get('key', '')).lower() == 'country':
                    value = str(item.get('value', '')).strip().upper()
                    if value:
                        country = value
                        break
            if country != '未知':
                break
    except Exception:
        pass

    cache[asn] = country
    profile = ASN_PROFILE_CACHE.setdefault(asn, {})
    profile['country'] = country
    return country


def _extract_name_from_asn(asn: int) -> str:
    if asn in ASN_PROFILE_CACHE and isinstance(ASN_PROFILE_CACHE[asn], dict):
        cached_name = ASN_PROFILE_CACHE[asn].get('name')
        if cached_name:
            return cached_name

    name = ''
    try:
        resp = requests.get(
            f'https://stat.ripe.net/data/whois/data.json?resource=AS{asn}',
            timeout=6,
            headers={'User-Agent': 'Mozilla/5.0'}
        )
        records = resp.json().get('data', {}).get('records', [])
        for group in records:
            for item in group:
                key = str(item.get('key', '')).lower()
                value = str(item.get('value', '')).strip()
                if key in ('as-name', 'org-name', 'organisation', 'descr') and value:
                    name = value
                    break
            if name:
                break
    except Exception:
        pass

    profile = ASN_PROFILE_CACHE.setdefault(asn, {})
    if name:
        profile['name'] = name
    return name


def query_routing_intel(asn_text: str) -> Dict:
    intel = {
        'asn': asn_text,
        'upstreams_guess': [],
        't1_transit': [],
        'interconnect_networks': [],
        'interconnect_countries': [],
        'source': 'RIPE ASN Neighbours',
    }
    asn_num = _parse_asn_int(asn_text)
    if not asn_num:
        return intel

    try:
        resp = requests.get(
            f'https://stat.ripe.net/data/asn-neighbours/data.json?resource=AS{asn_num}',
            timeout=15,
            headers={'User-Agent': 'Mozilla/5.0'}
        )
        neighbours = resp.json().get('data', {}).get('neighbours', [])
    except Exception as e:
        logger.warning('RIPE asn-neighbours failed: %s', e)
        return intel

    upstreams = []
    t1_hits = set()
    country_count = {}
    whois_cache: Dict[int, str] = {}

    valid_neighbours = [n for n in neighbours if isinstance(n.get('asn'), int)]
    valid_neighbours.sort(key=lambda x: int(x.get('power') or 0), reverse=True)

    # 控制耗时：关系分析取前 80，国家统计取前 24
    top_for_rel = valid_neighbours[:80]
    top_for_country = valid_neighbours[:24]

    for n in top_for_rel:
        n_asn = n.get('asn')
        rel_type = str(n.get('type', '')).lower()
        power = int(n.get('power') or 0)
        if rel_type == 'left':
            upstreams.append((n_asn, power))
        if n_asn in T1_ASN_MAP:
            t1_hits.add(n_asn)

    for n in top_for_country:
        n_asn = n.get('asn')
        c = _extract_country_from_asn(n_asn, whois_cache)
        country_count[c] = country_count.get(c, 0) + 1

    upstreams.sort(key=lambda x: x[1], reverse=True)
    intel['upstreams_guess'] = []
    for asn, power in upstreams[:8]:
        name = _extract_name_from_asn(asn)
        if name:
            intel['upstreams_guess'].append(f'AS{asn} {name} (power={power})')
        else:
            intel['upstreams_guess'].append(f'AS{asn} (power={power})')
    intel['t1_transit'] = [f'AS{asn} {T1_ASN_MAP.get(asn, "")}'.strip() for asn in sorted(t1_hits)]

    # RIPE 视角下的互联网络（按 power）
    interconnect_networks = []
    for n in valid_neighbours[:12]:
        n_asn = n.get('asn')
        power = int(n.get('power') or 0)
        name = _extract_name_from_asn(n_asn)
        if name:
            interconnect_networks.append(f'AS{n_asn} {name} (power={power})')
        else:
            interconnect_networks.append(f'AS{n_asn} (power={power})')
    intel['interconnect_networks'] = _uniq_keep_order(interconnect_networks)

    sorted_countries = sorted(country_count.items(), key=lambda kv: kv[1], reverse=True)
    intel['interconnect_countries'] = [f'{country}({count})' for country, count in sorted_countries[:8]]
    return intel


def query_prefix_connectivity(route_prefix: str) -> Dict:
    intel = {
        'upstreams_guess': [],
        't1_transit': [],
        'interconnect_networks': [],
        'interconnect_countries': [],
        'source': 'bgp.tools Prefix Connectivity',
    }
    prefix = str(route_prefix or '').strip()
    if not prefix or prefix == '未知':
        return intel

    try:
        ipaddress.ip_network(prefix, strict=False)
    except Exception:
        return intel

    session = f'bgpint-{uuid.uuid4().hex[:8]}'
    try:
        run_cmd(['/usr/local/bin/agent-browser', '--session-name', session, 'open', f'https://bgp.tools/prefix/{prefix}#connectivity'], timeout=45)
        run_cmd(['/usr/local/bin/agent-browser', '--session-name', session, 'wait', '--load', 'networkidle'], timeout=35)
        time.sleep(1)
        raw = browser_eval(session, """(function() {
  function norm(s) {
    return (s || '').toLowerCase().trim();
  }

  function uniqByAsn(rows) {
    const out = [];
    const seen = new Set();
    for (const r of (rows || [])) {
      if (!r || !r.asn || seen.has(r.asn)) continue;
      seen.add(r.asn);
      out.push(r);
    }
    return out;
  }

  function parseTableAfterH3(keyword) {
    const hs = Array.from(document.querySelectorAll('h3'));
    const h = hs.find(x => norm(x.innerText) === keyword);
    if (!h) return [];
    let el = h.nextElementSibling;
    while (el && el.tagName !== 'TABLE') {
      if (/^H[1-6]$/.test(el.tagName || '')) return [];
      el = el.nextElementSibling;
    }
    if (!el) return [];
    return Array.from(el.querySelectorAll('tbody tr')).map(tr => {
      const tds = Array.from(tr.querySelectorAll('td')).map(td => {
        const txt = (td.innerText || '').replaceAll('\\n', ' ').replaceAll('\\r', ' ');
        return txt.trim();
      });
      const joined = tds.join(' ');
      const m = joined.match(/AS([0-9]+)/i);
      return {
        country: (tds[0] || '未知').trim() || '未知',
        asn: m ? parseInt(m[1], 10) : null,
        asn_text: m ? `AS${m[1]}` : '',
        desc: (tds[tds.length - 1] || '').trim(),
      };
    }).filter(x => x.asn);
  }

  function parseListAfterH2(keyword) {
    const hs = Array.from(document.querySelectorAll('h2'));
    const h = hs.find(x => norm(x.innerText) === keyword);
    if (!h) return [];
    let el = h.nextElementSibling;
    while (el && el.tagName !== 'UL') {
      if (/^H[1-6]$/.test(el.tagName || '')) return [];
      el = el.nextElementSibling;
    }
    if (!el) return [];
    return Array.from(el.querySelectorAll('li')).map(li => {
      const txt = (li.innerText || '').replaceAll('\\n', ' ').replaceAll('\\r', ' ').trim();
      const m = txt.match(/AS([0-9]+)/i);
      return {
        country: '未知',
        asn: m ? parseInt(m[1], 10) : null,
        asn_text: m ? `AS${m[1]}` : '',
        desc: txt,
      };
    }).filter(x => x.asn);
  }

  const upstreamsTable = parseTableAfterH3('upstreams');
  const peers = parseTableAfterH3('peers');
  const upstreamsList = parseListAfterH2('upstreams');

  return JSON.stringify({
    upstreams: uniqByAsn([...(upstreamsTable || []), ...(upstreamsList || [])]),
    peers: uniqByAsn(peers || []),
  });
})()""", timeout=40)
        data = safe_json_loads(raw)
        if not isinstance(data, dict):
            return intel

        upstreams = data.get('upstreams') or []
        peers = data.get('peers') or []
        if not upstreams and not peers:
            return intel

        intel['upstreams_guess'] = [f"AS{x['asn']} {x.get('desc', '')}".strip() for x in upstreams[:8]]

        t1_hits = set()
        # 只按 upstream 计算 T1，避免把 peers 混进来导致与路径图口径偏差
        for x in upstreams:
            asn = int(x.get('asn'))
            if asn in T1_ASN_MAP:
                t1_hits.add(asn)
        intel['t1_transit'] = [f'AS{asn} {T1_ASN_MAP.get(asn, "")}'.strip() for asn in sorted(t1_hits)]
        intel['interconnect_networks'] = _uniq_keep_order([
            f"AS{x['asn']} {x.get('desc', '')}".strip() for x in (upstreams + peers)[:12]
        ])

        country_count: Dict[str, int] = {}
        for x in upstreams + peers:
            c = str(x.get('country') or '未知').strip().upper()
            if not c:
                c = '未知'
            country_count[c] = country_count.get(c, 0) + 1
        sorted_countries = sorted(country_count.items(), key=lambda kv: kv[1], reverse=True)
        intel['interconnect_countries'] = [f'{country}({count})' for country, count in sorted_countries[:8]]
        return intel
    except Exception as e:
        logger.warning('bgp.tools connectivity parse failed: %s', e)
        return intel
    finally:
        close_browser_session(session)


def _extract_asn_from_text(text: str) -> Optional[int]:
    m = re.search(r'AS(\d+)', str(text or ''), re.IGNORECASE)
    return int(m.group(1)) if m else None


def _uniq_keep_order(items: List[str]) -> List[str]:
    out: List[str] = []
    seen = set()
    for x in items:
        if not x or x in seen:
            continue
        seen.add(x)
        out.append(x)
    return out


def _uniq_by_asn(items: List[str]) -> List[str]:
    out: List[str] = []
    seen_asn = set()
    seen_text = set()
    for item in items:
        if not item:
            continue
        asn = _extract_asn_from_text(item)
        if asn is not None:
            if asn in seen_asn:
                continue
            seen_asn.add(asn)
            out.append(item)
            continue
        if item in seen_text:
            continue
        seen_text.add(item)
        out.append(item)
    return out


def merge_routing_intel(route_prefix: str, asn_text: str) -> Dict:
    """多源合并：优先 prefix 视角，RIPE 做交叉校验与补全。"""
    pfx = query_prefix_connectivity(route_prefix)
    ripe = query_routing_intel(asn_text)

    p_up = pfx.get('upstreams_guess') or []
    r_up = ripe.get('upstreams_guess') or []
    p_t1 = pfx.get('t1_transit') or []
    r_t1 = ripe.get('t1_transit') or []
    p_net = pfx.get('interconnect_networks') or []
    r_net = ripe.get('interconnect_networks') or []
    p_cty = pfx.get('interconnect_countries') or []
    r_cty = ripe.get('interconnect_countries') or []

    p_asn_set = {_extract_asn_from_text(x) for x in p_up}
    r_asn_set = {_extract_asn_from_text(x) for x in r_up}
    p_asn_set.discard(None)
    r_asn_set.discard(None)
    overlap_asn = p_asn_set & r_asn_set

    verified_up = [x for x in p_up if _extract_asn_from_text(x) in overlap_asn]
    merged_up = _uniq_by_asn(verified_up + p_up + r_up)
    merged_t1 = _uniq_keep_order(p_t1 + r_t1)
    merged_net = _uniq_by_asn(p_net + r_net)
    merged_cty = _uniq_keep_order(p_cty + r_cty)

    if p_up and overlap_asn:
        source = 'bgp.tools Prefix Connectivity + RIPE(已交叉校验)'
    elif p_up:
        source = 'bgp.tools Prefix Connectivity + RIPE(补充)'
    elif r_up:
        source = 'RIPE ASN Neighbours(回退)'
    else:
        source = 'bgp.tools+RIPE(无有效上游数据)'

    return {
        'upstreams_guess': merged_up,
        't1_transit': merged_t1,
        'interconnect_networks': merged_net,
        'interconnect_countries': merged_cty,
        'source': source,
    }


def _wait_itdog_results(session: str, max_wait: int) -> str:
    """轮询等待 itdog 出现结果，最长 max_wait 秒，返回原始 JSON."""
    interval = 3
    waited = 0
    while waited < max_wait:
        time.sleep(interval)
        waited += interval
        try:
            raw = browser_eval(session, """(function() {
var rows = Array.from(document.querySelectorAll('table tbody tr')).map(function(tr) {
  return Array.from(tr.querySelectorAll('td')).map(function(td) {
    return td.innerText.replace(/\\n+/g, ' ').trim();
  });
}).filter(function(cells) { return cells.length >= 9 && cells[0]; });
if (rows.length > 0) {
  return JSON.stringify(rows.map(function(cells) {
    return {
      node: cells[0] || '',
      response_ip: cells[1] || '',
      ip_location: cells[2] || '',
      loss: cells[3] || '',
      sent: cells[4] || '',
      latest: cells[5] || '',
      fastest: cells[6] || '',
      slowest: cells[7] || '',
      average: cells[8] || ''
    };
  }));
}
return 'EMPTY';
})()""", timeout=30)
            if raw and raw != 'EMPTY':
                return raw
        except Exception:
            pass
    return ''


def _parse_refs(snap_output: str) -> tuple:
    """从 snapshot -i 输出里解析 ref。"""
    ref_input = None
    ref_continuous = None
    for line in snap_output.splitlines():
        if ('请输入域名' in line or '请输入IP' in line) and not ref_input:
            m = re.search(r'\[ref=([^\]]+)\]', line)
            if m:
                ref_input = m.group(1)
        if '持续测试' in line and not ref_continuous:
            m = re.search(r'\[ref=([^\]]+)\]', line)
            if m:
                ref_continuous = m.group(1)
    return ref_input, ref_continuous


def extract_itdog_rows(session: str, ip: str, wait_seconds: int) -> List[Dict]:
    run_cmd(['/usr/local/bin/agent-browser', '--session-name', session, 'open', ITDOG_URL], timeout=60)
    run_cmd(['/usr/local/bin/agent-browser', '--session-name', session, 'wait', '--load', 'networkidle'], timeout=60)

    # 第一步：抓输入框，填 IP
    snap1 = run_cmd(['/usr/local/bin/agent-browser', '--session-name', session, 'snapshot', '-i'], timeout=30)
    ref_input = None
    for line in snap1.splitlines():
        if '请输入域名' in line or '请输入IP' in line:
            m = re.search(r'\[ref=([^\]]+)\]', line)
            if m:
                ref_input = m.group(1)
                break

    if not ref_input:
        raise RuntimeError('itdog 输入框未找到')

    run_cmd(['/usr/local/bin/agent-browser', '--session-name', session, 'fill', f'@{ref_input}', ip], timeout=15)

    # 第二步：重新抓 snapshot，此时按钮已渲染
    snap2 = run_cmd(['/usr/local/bin/agent-browser', '--session-name', session, 'snapshot', '-i'], timeout=30)
    ref_continuous = None
    for line in snap2.splitlines():
        if '持续测试' in line:
            m = re.search(r'\[ref=([^\]]+)\]', line)
            if m:
                ref_continuous = m.group(1)
                break

    if not ref_continuous:
        raise RuntimeError('持续测试按钮未找到')

    run_cmd(['/usr/local/bin/agent-browser', '--session-name', session, 'click', f'@{ref_continuous}'], timeout=15)

    # 轮询等结果
    interval = 4
    elapsed = 0
    last_error = ''
    while elapsed < wait_seconds:
        time.sleep(interval)
        elapsed += interval
        try:
            raw = browser_eval(session, """(function() {
var rows = Array.from(document.querySelectorAll('table tbody tr')).map(function(tr) {
  return Array.from(tr.querySelectorAll('td')).map(function(td) {
    return td.innerText.replace(/\\n+/g, ' ').trim();
  });
}).filter(function(cells) { return cells.length >= 9 && cells[0]; });
if (rows.length > 0) {
  return JSON.stringify(rows.slice(0,200).map(function(cells) {
    return {
      node: cells[0] || '',
      response_ip: cells[1] || '',
      ip_location: cells[2] || '',
      loss: cells[3] || '',
      sent: cells[4] || '',
      latest: cells[5] || '',
      fastest: cells[6] || '',
      slowest: cells[7] || '',
      average: cells[8] || ''
    };
  }));
}
return null;
})()""", timeout=30)
            if raw and raw != 'null' and raw.strip():
                rows = safe_json_loads(raw)
                if isinstance(rows, list) and len(rows) > 0:
                    return rows
        except Exception as e:
            last_error = str(e)

    raise RuntimeError(f'itdog 等待结果超时 (最后错误: {last_error})')



def close_browser_session(session: str) -> None:
    try:
        subprocess.run(
            ['/usr/local/bin/agent-browser', '--session-name', session, 'close'],
            capture_output=True,
            text=True,
            timeout=20,
        )
    except Exception:
        pass


def parse_ms(value: str) -> Optional[float]:
    value = str(value).strip()
    if not value or value in ('--', '超时'):
        return None
    if value.startswith('<'):
        return 1.0
    m = re.search(r'([\d.]+)', value)
    return float(m.group(1)) if m else None


def parse_percent(value: str) -> Optional[float]:
    m = re.search(r'([\d.]+)', str(value))
    return float(m.group(1)) if m else None


def summarize_rows(rows: List[Dict]) -> Dict:
    return {
        'focus_rows': summarize_focus_rows(rows),
        'overseas_rows': summarize_overseas_rows(rows),
        'total_rows': len(rows),
    }


def format_focus_rows(rows: List[Dict]) -> List[str]:
    lines: List[str] = []
    if not rows:
        return ['- 广东/广西 三网节点暂未抓到结果']
    for item in rows:
        avg_ms = f"{item['avg_ms']}ms" if item.get('avg_ms') is not None else '--'
        avg_loss = f"{item['avg_loss']}%" if item.get('avg_loss') is not None else '--'
        lines.append(
            f"- {item['group']}: 平均{avg_ms} 丢包{avg_loss} | 最优 {item['best_node']} ({item['best_avg']} / {item['best_loss']})"
        )
    return lines


def format_overseas_rows(rows: List[Dict]) -> List[str]:
    lines: List[str] = []
    if not rows:
        return ['- 美国/日本/新加坡/德国 节点暂未抓到结果']
    for item in rows:
        avg_ms = f"{item['avg_ms']}ms" if item.get('avg_ms') is not None else '--'
        avg_loss = f"{item['avg_loss']}%" if item.get('avg_loss') is not None else '--'
        lines.append(
            f"- {item['group']}: 平均{avg_ms} 丢包{avg_loss} | 最优 {item['best_node']} ({item['best_avg']} / {item['best_loss']})"
        )
    return lines


def _pathimg_url(route_prefix: str) -> str:
    prefix = str(route_prefix or '').strip()
    if not prefix or prefix == '未知':
        return ''
    return f"https://bgp.tools/pathimg/rt-{prefix.replace('/', '_')}"


def format_summary(ip: str, meta: Dict, dnsbl: Dict, rows: List[Dict]) -> str:
    data = summarize_rows(rows)
    focus_rows = data['focus_rows']

    routing = merge_routing_intel(meta.get('route', ''), meta.get('asn', ''))

    lines = []
    lines.append(f'IP 分析: {ip}')
    lines.append('')
    lines.append('基础信息')
    lines.append(f'- ASN: {meta["asn"]}')
    lines.append(f'- 持有者: {meta["holder"]}')
    lines.append(f'- 国家/地区: {meta["country"]}')
    lines.append(f'- 组织: {meta["org"]}')
    lines.append(f'- 路由前缀: {meta["route"]}')
    lines.append(f'- 纯净度: {dnsbl["status"]}')
    lines.append('')
    lines.append(f'itdog 国内聚焦: 广东/广西 三网，命中 {len(focus_rows)} 组')
    lines.extend(format_focus_rows(focus_rows))

    lines.append('')
    lines.append('BGP 路由情报')
    lines.append(f'- 数据源: {routing.get("source", "未知")}')
    t1_ref = [f"AS{asn} {name}" for asn, name in sorted(T1_ASN_MAP.items())]
    lines.append(f"- Tier1 参考: {' / '.join(t1_ref)}")

    upstreams = routing.get('upstreams_guess') or []
    t1s = routing.get('t1_transit') or []
    nets = routing.get('interconnect_networks') or []
    countries = routing.get('interconnect_countries') or []

    for item in upstreams[:3]:
        lines.append(f'- 上游: {item}')
    if not upstreams:
        lines.append('- 上游: 暂无')

    for item in t1s[:5]:
        lines.append(f'- T1: {item}')
    if not t1s:
        lines.append('- T1: 暂无')

    for item in nets[:5]:
        lines.append(f'- 互联网络: {item}')
    if not nets:
        lines.append('- 互联网络: 暂无')

    for item in countries[:5]:
        lines.append(f'- 互联国家: {item}')
    if not countries:
        lines.append('- 互联国家: 暂无')

    return '\n'.join(lines)


def format_full_rows(title: str, rows: List[Dict]) -> str:
    lines = [title]
    for r in rows:
        lines.append(
            f'- {r["node"]}: 平均 {r["average"]}ms，最快 {r["fastest"]}ms，最慢 {r["slowest"]}ms，丢包 {r["loss"]}，发包 {r["sent"]}'
        )
    return '\n'.join(lines)


def analyze_ip_sync(ip: str, wait_seconds: int) -> Dict:
    meta = query_ip_meta(ip)
    dnsbl = check_dnsbl(ip)
    session = f'itdog-{uuid.uuid4().hex[:10]}'
    try:
        rows = extract_itdog_rows(session, ip, wait_seconds)
    finally:
        close_browser_session(session)
    summary = summarize_rows(rows)
    return {
        'meta': meta,
        'dnsbl': dnsbl,
        'rows': rows,
        'summary': summary,
    }


async def start_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        '发 IP 给我。\n'
        '我会返回：\n'
        '1. ASN / 路由 / 归属\n'
        '2. 基础纯净度(DNSBL)\n'
        '3. itdog 国内：仅广东/广西 电信联通移动\n'
        '4. BGP：上游猜测 / T1 接入 / 互联网络 / 国际互联国家'
    )


async def status_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    cfg = load_config()
    admin_id = cfg.get('telegram', {}).get('admin_id') or '未设置'
    wait_seconds = cfg.get('itdog_wait_seconds', ITDOG_WAIT_SECONDS)
    await update.message.reply_text(
        '运行状态\n'
        f'- bot: 在线\n'
        f'- itdog 持续测试等待: {wait_seconds}s\n'
        f'- only_admin: {cfg.get("only_admin", False)}\n'
        f'- admin_id: {admin_id}'
    )


async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.message or not update.message.text:
        return

    cfg = load_config()
    admin_id = str(cfg.get('telegram', {}).get('admin_id', '')).strip()
    only_admin = bool(cfg.get('only_admin', False))
    from_user_id = str(update.effective_user.id)

    if only_admin and admin_id and from_user_id != admin_id:
        await update.message.reply_text('未授权用户')
        return

    ips = parse_ips(update.message.text)
    if not ips:
        return

    wait_seconds = min(int(cfg.get('itdog_wait_seconds', ITDOG_WAIT_SECONDS)), 30)

    for ip in ips[:3]:
        progress = await update.message.reply_text(f'开始分析 {ip}，正在跑 itdog 持续测试，大约 {wait_seconds}s ...')
        try:
            result = await asyncio.to_thread(analyze_ip_sync, ip, wait_seconds)
            summary_text = format_summary(ip, result['meta'], result['dnsbl'], result['rows'])
            await progress.edit_text(summary_text)
        except Exception as e:
            import traceback
            logger.exception('analyze failed')
            await progress.edit_text(f'分析失败: {type(e).__name__}: {e}\n\n{traceback.format_exc()[-300:]}')


def build_app() -> Application:
    cfg = load_config()
    token = cfg.get('telegram', {}).get('bot_token', '').strip()
    if not token:
        raise RuntimeError('未配置 telegram.bot_token')

    app = Application.builder().token(token).build()
    app.add_handler(CommandHandler('start', start_cmd))
    app.add_handler(CommandHandler('status', status_cmd))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    return app


def interactive_init() -> None:
    print('=========================================')
    print('  ip test 安装配置')
    print('=========================================')
    token = input('TG Bot Token: ').strip()
    admin_id = input('管理员 TG ID(可留空): ').strip()
    wait_seconds = input(f'itdog 持续测试等待秒数 [{ITDOG_WAIT_SECONDS}]: ').strip() or str(ITDOG_WAIT_SECONDS)
    only_admin = input('是否仅管理员可用? [y/N]: ').strip().lower() == 'y'

    cfg = DEFAULT_CONFIG.copy()
    cfg['telegram'] = {'bot_token': token, 'admin_id': admin_id}
    cfg['itdog_wait_seconds'] = int(wait_seconds)
    cfg['only_admin'] = only_admin
    save_config(cfg)
    print(f'配置已写入 {CONFIG_FILE}')


def main():
    os.makedirs(APP_DIR, exist_ok=True)
    lock_path = f'{APP_DIR}/bot.lock'
    lock_fp = open(lock_path, 'w')
    try:
        fcntl.flock(lock_fp.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        logger.error('bot 已有实例在运行，退出')
        return

    if not os.path.exists(CONFIG_FILE):
        interactive_init()

    cfg = load_config()
    token = cfg.get('telegram', {}).get('bot_token', '').strip()
    if token:
        try:
            requests.get(f'https://api.telegram.org/bot{token}/deleteWebhook?drop_pending_updates=true', timeout=15)
            logger.info('已清理 webhook / pending updates')
        except Exception as e:
            logger.warning('deleteWebhook failed: %s', e)

    app = build_app()
    logger.info('TG Bot 启动')
    app.run_polling(drop_pending_updates=True)


if __name__ == '__main__':
    main()
