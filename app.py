#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import asyncio
from collections import Counter
import fcntl
import ipaddress
import json
import logging
import os
import re
import urllib.request
import urllib.error
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
    174: 'Cogent',
    2914: 'NTT',
    4637: 'Telstra',
    5511: 'Orange',
    6939: 'Hurricane Electric',
    6461: 'Zayo',
    9002: 'RETN',
}

T1_DESCRIPTIONS = {
    1299: '北欧骨干，欧洲最强 T1',
    174: '美国最大对等网之一，Cogent',
    2914: '日本 NTT，全球第二大骨干',
    3257: 'GTT，美国跨大西洋骨干',
    3320: '德国电信 DTAG 骨干',
    3356: '原 Level 3，Lumen 骨干',
    3491: '电讯盈科，PCCW 亚太骨干',
    4637: 'Telstra，澳洲最大骨干',
    5511: 'Orange，法国电信全球骨干',
    6453: 'Tata 通信，印度全球骨干',
    6461: 'Zayo，北美光纤骨干',
    6762: 'Sparkle，意大利电信骨干',
    6939: 'Hurricane Electric，北美骨干',
    7018: 'AT&T，美国骨干',
    12956: '西班牙电信海底光缆子公司',
    9002: 'RETN，欧洲跨骨干',
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
    candidates = re.findall(r'\b(?:(?:\d{1,3}\.){3}\d{1,3})\b|\b[0-9a-fA-F:]{2,}\b', text)
    result = []
    for item in candidates:
        if is_valid_ip(item) and item not in result:
            result.append(item)
    return result


def extract_domains(text: str) -> List[str]:
    """从文本中提取疑似域名（排除纯 IP，支持 www. 和 http(s):// 前缀）。"""
    # 先去掉协议头
    text = re.sub(r'https?://', '', text)
    # 匹配多级域名：sub.domain.example.co.uk
    domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
    candidates = re.findall(domain_pattern, text)
    result = []
    for item in candidates:
        if is_valid_ip(item):
            continue
        # 过滤常见非域名噪声
        if len(item) < 4:
            continue
        if item in result:
            continue
        result.append(item)
    return result


def resolve_domains(domains: List[str]) -> Dict[str, str]:
    """DNS 解析域名列表，返回 {domain: ip} 映射，失败记录日志。"""
    resolved = {}
    for d in domains:
        try:
            ip = socket.gethostbyname(d)
            resolved[d] = ip
            logger.info('DNS %s → %s', d, ip)
        except socket.gaierror as e:
            logger.warning('DNS 解析失败 %s: %s', d, e)
        except Exception as e:
            logger.warning('DNS 异常 %s: %s', d, e)
    return resolved


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
    """Run JS via /root/.nvm/versions/node/v24.14.0/bin/agent-browser eval --stdin, return stdout."""
    cmd = ['/root/.nvm/versions/node/v24.14.0/bin/agent-browser', '--session-name', session, 'eval', '--stdin']
    proc = subprocess.run(
        cmd,
        input=script,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    out = (proc.stdout or '').strip()
    logger.info('browser_eval out length: %s, out: %s', len(out), out[:200])
    if proc.returncode != 0:
        err = (proc.stderr or '').strip()
        logger.warning('browser_eval failed rc=%d: %s', proc.returncode, err)
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

    # 静态常见 ASN 名称映射（RIPE 查询失败时的后备）
    COMMON_ASN_NAMES = {
        13335: 'Cloudflare, Inc.',
        15169: 'Google LLC',
        16509: 'Amazon.com, Inc.',
        14618: 'Amazon.com, Inc.',
        8075: 'Microsoft Corporation',
        139070: 'Microsoft Corporation',
        3356: 'Lumen (Level 3)',
        1299: 'Arelion (Telia Carrier)',
        174: 'Cogent Communications',
        2914: 'NTT America',
        3257: 'GTT Communications',
        3320: 'Deutsche Telekom AG',
        3491: 'PCCW Global',
        5511: 'Orange S.A.',
        6453: 'TATA Communications',
        6762: 'Telecom Italia Sparkle',
        7018: 'AT&T Enterprises',
        12956: 'Telxius (Telefonica Global)',
        4637: 'Telstra International',
        7474: 'SingTel Optus',
        6939: 'Hurricane Electric',
        9516: 'SAKURA LINK LIMITED',
        49304: 'SAKURA LINK LIMITED',
    }
    if asn in COMMON_ASN_NAMES:
        name = COMMON_ASN_NAMES[asn]
        profile = ASN_PROFILE_CACHE.setdefault(asn, {})
        profile['name'] = name
        return name

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
        'as_path': '',
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
        # 重试打开页面，最多4次
        max_retries = 4
        for attempt in range(max_retries):
            try:
                run_cmd(['/root/.nvm/versions/node/v24.14.0/bin/agent-browser', '--session-name', session, 'open', f'https://bgp.tools/prefix/{prefix}#connectivity'], timeout=60)
                run_cmd(['/root/.nvm/versions/node/v24.14.0/bin/agent-browser', '--session-name', session, 'wait', '--load', 'networkidle'], timeout=45)
                time.sleep(2)
                break
            except RuntimeError as e:
                if attempt == max_retries - 1:
                    raise
                logger.warning('bgp.tools 页面打开失败，重试 %d/%d: %s', attempt + 1, max_retries, e)
                time.sleep(3)
        # 重试获取数据，最多3次
        upstreams = []
        peers = []
        for eval_retry in range(3):
            try:
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
    const h = hs.find(x => norm(x.innerText).includes(keyword));
    if (!h) return [];
    let el = h.nextElementSibling;
    while (el && el.tagName !== 'TABLE') {
      if (/^H[1-6]$/.test(el.tagName || '')) return [];
      el = el.nextElementSibling;
    }
    if (!el) return [];
    return Array.from(el.querySelectorAll('tbody tr')).map(tr => {
      const tds = Array.from(tr.querySelectorAll('td')).map(td => {
        const txt = (td.innerText || '').replaceAll('\\\\n', ' ').replaceAll('\\\\r', ' ');
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
    const h = hs.find(x => norm(x.innerText).includes(keyword));
    if (!h) return [];
    let el = h.nextElementSibling;
    while (el && el.tagName !== 'UL') {
      if (/^H[1-6]$/.test(el.tagName || '')) return [];
      el = el.nextElementSibling;
    }
    if (!el) return [];
    return Array.from(el.querySelectorAll('li')).map(li => {
      const txt = (li.innerText || '').replaceAll('\\\\n', ' ').replaceAll('\\\\r', ' ').trim();
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
                if isinstance(data, dict):
                    upstreams = data.get('upstreams') or []
                    peers = data.get('peers') or []
                    if upstreams or peers:
                        break
            except Exception as e:
                logger.warning('bgp.tools eval 重试 %d/3 失败: %s', eval_retry + 1, e)
            time.sleep(1)
        
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


def _ripe_whois_batch(asns: List[int]) -> dict:
    """批量查 RIPE whois 获取多个 ASN 的 country/name，带进程内缓存。"""
    global _ripe_whois_global_cache
    cache = _ripe_whois_global_cache
    need = [a for a in asns if a not in cache]
    if not need:
        return cache
    from concurrent.futures import ThreadPoolExecutor, as_completed
    def _fetch_one(asn):
        result = {'country': '', 'name': '', 'as_name': ''}
        try:
            req = urllib.request.Request(
                f'https://stat.ripe.net/data/whois/data.json?resource=AS{asn}',
                headers={'User-Agent': 'acmeco-ripe-lookup/1.0'})
            with urllib.request.urlopen(req, timeout=8) as resp:
                data = json.load(resp)
            for rec in data.get('data', {}).get('records', [[]])[0]:
                key = rec.get('key', '').lower()
                val = rec.get('value', '')
                if key == 'country':
                    result['country'] = val
                elif key in ('as-name', 'asname'):
                    result['as_name'] = val
                elif key == 'descr' and not result['name']:
                    result['name'] = val
        except Exception:
            pass
        return asn, result
    with ThreadPoolExecutor(max_workers=12) as ex:
        futures = {ex.submit(_fetch_one, a): a for a in need}
        for fut in as_completed(futures):
            asn, res = fut.result()
            cache[asn] = res
    return cache

_ripe_whois_global_cache = {}


def query_upstream_from_ripe(prefix: str, asn_text: str = '') -> dict:
    """从 RIPE Stat BGP State + WhoIs 提取完整路由情报（无 bgp.tools 依赖）"""
    intel = {
        'upstreams_guess': [],
        't1_transit': [],
        'interconnect_networks': [],
        'interconnect_countries': [],
        'as_path': '',
        'source': 'RIPE Stat'
    }
    try:
        target_asn = None
        if asn_text:
            m = re.search(r'AS(\d+)', asn_text)
            if m:
                target_asn = int(m.group(1))
        if target_asn is None:
            return intel

        # retry 500/502/503/504 错误
        for ripe_retry in range(3):
            try:
                url = f'https://stat.ripe.net/data/bgp-state/data.json?resource={prefix}'
                with urllib.request.urlopen(url, timeout=15) as resp:
                    data = json.load(resp)
                break
            except urllib.error.HTTPError as e:
                if e.code in (500, 502, 503, 504) and ripe_retry < 2:
                    logger.warning('RIPE 返回 %d，重试 %d/2', e.code, ripe_retry + 1)
                    time.sleep(2)
                    continue
                raise

        bgp_paths = data.get('data', {}).get('bgp_state', [])
        if not bgp_paths:
            return intel

        # AS Path：取第一条路径（最常见路径）
        first_path = bgp_paths[0].get('path', [])
        if first_path:
            intel['as_path'] = ' '.join([f'AS{a}' for a in first_path])

        known_t1 = set(T1_ASN_MAP.keys())

        upstream_counter = {}
        all_path_asns = set()
        asn_path_count = {}
        # T1：所有路径中出现过的 T1（不限位置），按出现频率排序
        all_t1_in_paths = Counter()
        for item in bgp_paths:
            path = item.get('path', [])
            all_path_asns.update(path)
            for asn in path:
                if asn != target_asn:
                    asn_path_count[asn] = asn_path_count.get(asn, 0) + 1
                if asn in known_t1:
                    all_t1_in_paths[asn] += 1
            # 上游：target AS 的直接前一跳
            try:
                idx = path.index(target_asn)
                if idx > 0:
                    upstream_asn = path[idx - 1]
                    upstream_counter[upstream_asn] = upstream_counter.get(upstream_asn, 0) + 1
            except ValueError:
                pass
        t1_asns = [asn for asn, _ in sorted(all_t1_in_paths.items(), key=lambda kv: kv[1], reverse=True)]

        # 一次性批量获取所有 ASN 的 whois 数据
        all_needed = list(all_path_asns)
        cache = _ripe_whois_batch(all_needed)

        sorted_up = sorted(upstream_counter.items(), key=lambda kv: kv[1], reverse=True)
        upstream_asns = [asn for asn, _ in sorted_up[:8]]

        # 上游
        intel['upstreams_guess'] = []
        for asn in upstream_asns:
            info = cache.get(asn, {})
            name = info.get('as_name') or info.get('name', '')
            cnt = upstream_counter[asn]
            intel['upstreams_guess'].append(
                f'AS{asn} {name} (power={cnt})' if name else f'AS{asn} (power={cnt})')

        # 互联网络（排除 target 和 upstream 本身）
        seen_up = set(upstream_asns)
        networks_out = []
        for asn, cnt in sorted(asn_path_count.items(), key=lambda kv: kv[1], reverse=True):
            if asn == target_asn or asn in seen_up:
                continue
            info = cache.get(asn, {})
            name = info.get('as_name') or info.get('name', '')
            networks_out.append(f'AS{asn} {name} (power={cnt})' if name else f'AS{asn} (power={cnt})')
            if len(networks_out) >= 15:
                break
        intel['interconnect_networks'] = networks_out

        # 互联国家
        country_counter = {}
        for asn in all_path_asns:
            if asn == target_asn:
                continue
            info = cache.get(asn, {})
            c = info.get('country', '')
            if c:
                country_counter[c] = country_counter.get(c, 0) + 1
        intel['interconnect_countries'] = [
            f'{c}({cnt})' for c, cnt in
            sorted(country_counter.items(), key=lambda kv: kv[1], reverse=True)[:8]]

        intel['t1_transit'] = [
            f'AS{asn} {T1_ASN_MAP.get(asn, "")} — {T1_DESCRIPTIONS.get(asn, "")} (power={all_t1_in_paths.get(asn, 0)})'
            for asn in t1_asns
        ]
        return intel
    except Exception as e:
        logger.warning('RIPE Stat upstream extraction failed: %s', e)
        return intel


def fetch_pathimg_t1(route_prefix: str) -> List[str]:
    """从 bgp.tools 路径图页面提取起源 AS 连接的 Tier‑1 ASN 列表（含名称）"""
    session = f'pathimg-{uuid.uuid4().hex[:8]}'
    try:
        # 打开路径图页面
        run_cmd(['/root/.nvm/versions/node/v24.14.0/bin/agent-browser', '--session-name', session, 'open', f'https://bgp.tools/pathimg/rt-{route_prefix.replace("/", "_")}'], timeout=60)
        run_cmd(['/root/.nvm/versions/node/v24.14.0/bin/agent-browser', '--session-name', session, 'wait', '--load', 'networkidle'], timeout=45)
        time.sleep(2)
        # 获取 snapshot 文本
        raw = browser_eval(session, """
(function() {
  // 查找所有 group 元素，通过 id 属性
  let groups = Array.from(document.querySelectorAll('g[id]'));
  let connections = [];
  let asNames = {};
  for (let g of groups) {
    let id = g.getAttribute('id');
    if (!id) continue;
    // 连接关系
    if (id.includes('->')) {
      let parts = id.split('->');
      if (parts.length === 2) {
        connections.push({ from: parts[0], to: parts[1] });
      }
    } else {
      // AS 名称
      let link = g.querySelector('a');
      if (link) {
        asNames[id] = link.textContent.trim();
      }
    }
  }
  return JSON.stringify({ connections, asNames });
})()
""", timeout=40)
        data = safe_json_loads(raw)
        if not isinstance(data, dict):
            return []
        connections = data.get('connections', [])
        asNames = data.get('asNames', {})
        
        # 检测起源 AS：找出所有作为起点但从不作为终点的 AS
        from_set = set()
        to_set = set()
        for conn in connections:
            from_as = conn.get('from')
            to_as = conn.get('to')
            if from_as and re.match(r'^AS\d+$', from_as):
                from_set.add(from_as)
            if to_as and re.match(r'^AS\d+$', to_as):
                to_set.add(to_as)
        origin_asns = list(from_set - to_set)  # 只出现在 from 中的 AS
        
        # 如果没有明确的起源，取第一个出现的 from AS 作为后备
        if not origin_asns and from_set:
            origin_asns = [next(iter(from_set))]
        
        # 收集从每个起源 AS 出发、目标为 Tier‑1 的连接
        t1_peers = []
        for origin in origin_asns:
            for conn in connections:
                if conn.get('from') == origin:
                    to_as = conn.get('to')
                    if not to_as:
                        continue
                    m = re.match(r'^AS(\d+)$', to_as)
                    if m:
                        asn_num = int(m.group(1))
                        if asn_num in T1_ASN_MAP:
                            name = asNames.get(to_as) or ''
                            t1_peers.append((asn_num, name))
        
        # 去重（按 ASN）
        seen = set()
        unique_peers = []
        for asn, name in t1_peers:
            if asn not in seen:
                seen.add(asn)
                unique_peers.append((asn, name))
        
        # 补全缺失的名称
        results = []
        for asn, name in unique_peers:
            if not name:
                name = _extract_name_from_asn(asn)
            results.append(f'AS{asn} {name}'.strip())
        return results
    except Exception as e:
        logger.warning('pathimg Tier‑1 peers extraction failed: %s', e)
        return []
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
    """并行调用 RIPE Stat + bgp.tools；默认以 bgp.tools 为主，RIPE 兜底补充。"""
    import concurrent.futures

    ripe_future = concurrent.futures.ThreadPoolExecutor(max_workers=1).submit(
        query_upstream_from_ripe, route_prefix, asn_text
    )
    bgp_future = concurrent.futures.ThreadPoolExecutor(max_workers=1).submit(
        query_prefix_connectivity, route_prefix
    )

    try:
        ripe = ripe_future.result(timeout=70)
    except Exception as e:
        logger.warning('RIPE query failed: %s: %r', type(e).__name__, e)
        ripe = {'t1_transit': [], 'upstreams_guess': [], 'interconnect_networks': [], 'interconnect_countries': [], 'as_path': '', 'source': 'RIPE Stat'}

    try:
        bgp = bgp_future.result(timeout=60)
    except Exception as e:
        logger.warning('bgp.tools query failed: %s', e)
        bgp = {'t1_transit': [], 'upstreams_guess': [], 'interconnect_networks': [], 'interconnect_countries': [], 'as_path': '', 'source': 'bgp.tools Prefix Connectivity'}

    bgp_up = bgp.get('upstreams_guess') or []
    ripe_up = ripe.get('upstreams_guess') or []
    bgp_net = bgp.get('interconnect_networks') or []
    ripe_net = ripe.get('interconnect_networks') or []
    bgp_cty = bgp.get('interconnect_countries') or []
    ripe_cty = ripe.get('interconnect_countries') or []

    # 上游/互联默认优先 bgp.tools，RIPE 仅兜底
    merged_up = bgp_up or ripe_up
    merged_net = bgp_net or ripe_net
    merged_cty = bgp_cty or ripe_cty

    # T1 合并去重（bgp 优先展示，RIPE 补充）
    merged_t1s: List[str] = []
    seen_t1_asns = set()
    for item in (bgp.get('t1_transit') or []) + (ripe.get('t1_transit') or []):
        m = re.search(r'AS(\d+)', str(item))
        if m:
            asn = int(m.group(1))
            if asn in seen_t1_asns:
                continue
            seen_t1_asns.add(asn)
        if item:
            merged_t1s.append(item)

    # 路径级 T1 兜底：当两源都没命中时，尝试 pathimg 抓取
    if not merged_t1s and route_prefix and route_prefix != '未知':
        pathimg_t1 = fetch_pathimg_t1(route_prefix)
        if pathimg_t1:
            merged_t1s = _uniq_by_asn(pathimg_t1)

    # as_path 目前只有 RIPE 提供
    as_path = ripe.get('as_path') or ''

    bgp_ok = bool(bgp_up or bgp_net or bgp_cty)
    ripe_ok = bool(ripe_up or ripe_net or ripe_cty or as_path)
    if bgp_ok and ripe_ok:
        source = 'bgp.tools Prefix Connectivity + RIPE Stat(补充)'
    elif bgp_ok:
        source = 'bgp.tools Prefix Connectivity'
    elif ripe_ok:
        source = 'RIPE Stat'
    else:
        source = 'bgp.tools + RIPE Stat（无有效数据）'

    return {
        'upstreams_guess': merged_up,
        't1_transit': merged_t1s,
        'interconnect_networks': merged_net,
        'interconnect_countries': merged_cty,
        'as_path': as_path,
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
    # 打开 itdog 页面，允许重试
    max_retries = 3
    for attempt in range(max_retries):
        try:
            run_cmd(['/root/.nvm/versions/node/v24.14.0/bin/agent-browser', '--session-name', session, 'open', ITDOG_URL], timeout=60)
            run_cmd(['/root/.nvm/versions/node/v24.14.0/bin/agent-browser', '--session-name', session, 'wait', '--load', 'networkidle'], timeout=60)
            break
        except RuntimeError as e:
            if attempt == max_retries - 1:
                raise
            logger.warning('itdog 页面打开失败，重试 %d/%d: %s', attempt + 1, max_retries, e)
            time.sleep(2)

    # 第一步：抓输入框，填 IP
    snap1 = run_cmd(['/root/.nvm/versions/node/v24.14.0/bin/agent-browser', '--session-name', session, 'snapshot', '-i'], timeout=30)
    ref_input = None
    for line in snap1.splitlines():
        if '请输入域名' in line or '请输入IP' in line:
            m = re.search(r'\[ref=([^\]]+)\]', line)
            if m:
                ref_input = m.group(1)
                break

    if not ref_input:
        raise RuntimeError('itdog 输入框未找到')

    run_cmd(['/root/.nvm/versions/node/v24.14.0/bin/agent-browser', '--session-name', session, 'fill', f'@{ref_input}', ip], timeout=15)

    # 第二步：重新抓 snapshot，此时按钮已渲染
    snap2 = run_cmd(['/root/.nvm/versions/node/v24.14.0/bin/agent-browser', '--session-name', session, 'snapshot', '-i'], timeout=30)
    ref_continuous = None
    for line in snap2.splitlines():
        if '持续测试' in line:
            m = re.search(r'\[ref=([^\]]+)\]', line)
            if m:
                ref_continuous = m.group(1)
                break

    if not ref_continuous:
        raise RuntimeError('持续测试按钮未找到')

    run_cmd(['/root/.nvm/versions/node/v24.14.0/bin/agent-browser', '--session-name', session, 'click', f'@{ref_continuous}'], timeout=15)

    # 轮询等结果（不要首屏有数据就立即返回，尽量等海外四国聚合齐）
    interval = 4
    elapsed = 0
    last_error = ''
    best_rows: List[Dict] = []
    best_overseas_count = 0
    target_overseas = {'美国', '日本', '新加坡', '德国'}

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
                    # 记录当前最好快照（按海外四国覆盖数优先，其次行数）
                    cur_groups = {detect_overseas_group(r) for r in rows if detect_overseas_group(r)}
                    cur_overseas_count = len(cur_groups & target_overseas)
                    if (cur_overseas_count > best_overseas_count) or (
                        cur_overseas_count == best_overseas_count and len(rows) > len(best_rows)
                    ):
                        best_rows = rows
                        best_overseas_count = cur_overseas_count

                    # 四国齐了，提前返回
                    if cur_overseas_count >= 4:
                        return rows
        except Exception as e:
            last_error = str(e)

    # 超时后返回最佳快照（避免只拿到首屏半成品）
    if best_rows:
        return best_rows

    raise RuntimeError(f'itdog 等待结果超时 (最后错误: {last_error})')



def close_browser_session(session: str) -> None:
    try:
        subprocess.run(
            ['/root/.nvm/versions/node/v24.14.0/bin/agent-browser', '--session-name', session, 'close'],
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
    order = ('美国', '日本', '新加坡', '德国')
    row_map = {item.get('group'): item for item in rows if item.get('group')}

    for country in order:
        item = row_map.get(country)
        if not item:
            lines.append(f'- {country}: 暂无有效结果（可能该轮未回传/排队中）')
            continue
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


def format_summary(ip: str, meta: Dict, dnsbl: Dict, rows: List[Dict], resolved_domain: Optional[str] = None) -> str:
    data = summarize_rows(rows)
    focus_rows = data['focus_rows']

    routing = merge_routing_intel(meta.get('route', ''), meta.get('asn', ''))

    lines = []
    lines.append(f'IP 分析: {ip}')
    if resolved_domain:
        lines.append(f'来源域名: {resolved_domain}')
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

    overseas_rows = data['overseas_rows']
    lines.append('')
    lines.append(f'itdog 海外: 美国/日本/新加坡/德国，命中 {len(overseas_rows)}/4 组')
    lines.extend(format_overseas_rows(overseas_rows))

    lines.append('')
    lines.append('BGP 路由情报')
    lines.append(f'- 数据源: {routing.get("source", "未知")}')

    as_path = routing.get('as_path', '')
    if as_path:
        parts = as_path.split()
        # 批量获取AS名称
        asn_list = [int(p.replace('AS', '')) for p in parts]
        _ripe_whois_batch(asn_list)
        cache = _ripe_whois_global_cache
        lines.append('- AS Path:')
        for i, p in enumerate(parts):
            asn = int(p.replace('AS', ''))
            info = cache.get(asn, {})
            name = info.get('as_name') or info.get('name', '')
            label = f'{p} {name}' if name else p
            if i == 0:
                lines.append(f'  {label}')
            else:
                lines.append(f'  ↓ {label}')
    else:
        lines.append('- AS Path: 暂无')

    upstreams = routing.get('upstreams_guess') or []
    if upstreams:
        lines.append(f'- 上游（共{len(upstreams)}条）')
        for item in upstreams[:10]:
            lines.append(f'  · {item}')
    else:
        lines.append('- 上游: 暂无')

    t1s = routing.get('t1_transit') or []
    if t1s:
        lines.append(f'- T1 in Path（共{len(t1s)}个）')
        for item in t1s:
            lines.append(f'  · {item}')
    else:
        lines.append('- T1 in Path: 暂无')

    # 分析注释
    asn_info = meta.get('asn', 'AS???')
    country_info = meta.get('country', '未知')
    holder_info = meta.get('holder', '')
    upstreams = routing.get('upstreams_guess') or []
    first_up = upstreams[0].split('(power')[0].strip() if upstreams else ''
    analysis_parts = []
    if 'HK' in country_info or 'Hong Kong' in country_info:
        asn_in_path = as_path.split()[-1] if as_path else ''
        if asn_in_path and f'AS' in asn_in_path:
            asn_num = asn_in_path.replace('AS', '')
            if asn_num not in asn_info:
                analysis_parts.append(f'⚠️ IP归属地={country_info}({holder_info})，但BGP路由源={as_path.split()[0]}（{as_path.split()[0].replace("AS","AS")}），两者不一致→该IP实际托管位置与注册归属不同')
    if t1s:
        analysis_parts.append(f'上游主要走{first_up}')
    if analysis_parts:
        lines.append('')
        for note in analysis_parts:
            lines.append(note)
        lines.append('ℹ️ T1 为 RIPE Stat + bgp.tools 并集采集，数据更全')

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

    # 兜底重试：若海外四国未齐，再补测一轮，取覆盖更多的结果
    first_overseas = len(summarize_overseas_rows(rows))
    if first_overseas < 4:
        retry_wait = min(max(wait_seconds, 45), 70)
        retry_session = f'itdog-{uuid.uuid4().hex[:10]}'
        try:
            retry_rows = extract_itdog_rows(retry_session, ip, retry_wait)
            retry_overseas = len(summarize_overseas_rows(retry_rows))
            if (retry_overseas > first_overseas) or (
                retry_overseas == first_overseas and len(retry_rows) > len(rows)
            ):
                rows = retry_rows
                first_overseas = retry_overseas
            logger.info('itdog fallback retry: first=%s retry=%s', first_overseas, retry_overseas)
        except Exception as e:
            logger.warning('itdog fallback retry failed: %s', e)
        finally:
            close_browser_session(retry_session)

    summary = summarize_rows(rows)
    return {
        'meta': meta,
        'dnsbl': dnsbl,
        'rows': rows,
        'summary': summary,
    }


async def start_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        '发 IP 或域名给我。\n'
        '我会返回：\n'
        '1. ASN / 路由 / 归属\n'
        '2. 基础纯净度(DNSBL)\n'
        '3. itdog 国内：仅广东/广西 电信联通移动\n'
        '4. BGP：AS Path / 上游 / T1 in Path'
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
    domains = extract_domains(update.message.text)
    resolved = resolve_domains(domains)
    domain_ips = list(resolved.values())
    all_ips = ips + [ip for ip in domain_ips if ip not in ips]
    if not all_ips:
        await update.message.reply_text('未识别到有效 IP 或域名，请输入 IP 地址或域名')
        return

    wait_seconds = min(int(cfg.get('itdog_wait_seconds', ITDOG_WAIT_SECONDS)), 60)

    # 建立 ip → 来源映射（域名或"直接输入"）
    ip_source: Dict[str, str] = {}
    for ip in ips:
        ip_source[ip] = ip
    for domain, ip in resolved.items():
        ip_source[ip] = domain

    for ip in all_ips[:3]:
        source = ip_source.get(ip, ip)
        label = f'域名 {source} → {ip}' if source != ip else ip
        progress = await update.message.reply_text(f'开始分析 {label}，正在跑 itdog 持续测试，大约 {wait_seconds}s ...')
        try:
            result = await asyncio.to_thread(analyze_ip_sync, ip, wait_seconds)
            summary_text = format_summary(ip, result['meta'], result['dnsbl'], result['rows'], resolved_domain=source if source != ip else None)
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
    print('  IP Analyzer Pro 安装配置')
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
