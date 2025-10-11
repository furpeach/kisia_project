import sys
import warnings
import os
import logging
import json
import re

warnings.filterwarnings("ignore")
os.environ["PYTHONWARNINGS"] = "ignore"
logging.getLogger().setLevel(logging.ERROR)

import requests
import time
from mcp.server.fastmcp import FastMCP
from decoding_hex import HexDecoder

from typing import List, Dict, Optional

import httpx
import asyncio
from datetime import datetime

import urllib3
from urllib3.exceptions import InsecureRequestWarning
urllib3.disable_warnings(InsecureRequestWarning)

from dataclasses import dataclass

mcp = FastMCP("QRadar API Server")

URL_BASE = os.environ.get("URL_BASE")
SEC_TOKEN = os.environ.get("SEC_TOKEN")
LOGSOURCE_ID = 163
QID = 1002750255
DEFAULT_OUTPUT_DIR = "C:\\Users\\KISIA\\Desktop\\bluescreen\\mcp\\rest_api_test\\qrdar_result_files"

@dataclass
class OffenseFilter:
    logsource_id: int = LOGSOURCE_ID
    start_time: Optional[int] = None
    end_time: Optional[int] = None

@dataclass
class SimilarityConfig:
    ip_score: int = 50
    rule_score: int = 30
    dest_score: int = 20
    threshold: int = 70
    max_results: int = 5

class AsyncQRadarClient:
    def __init__(self, base_url: str, sec_token: str):
        self.base_url = base_url
        self.headers = {
            'SEC': sec_token,
            'Content-Type': 'application/json',
            'accept': 'application/json'
        }
        self.timeout = 600.0
        self.endpoints = {
            'about': '/api/system/about',
            'offenses': '/api/siem/offenses',
            'offense_detail': '/api/siem/offenses/{}',
            'search': '/api/ariel/searches',
            'search_status': '/api/ariel/searches/{}',
            'search_results': '/api/ariel/searches/{}/results',
            'rules': '/api/analytics/rules/{}',
            'source_addresses': '/api/siem/source_addresses/{}',
            'local_destination_addresses': '/api/siem/local_destination_addresses/{}'
        }

    async def get(self, endpoint_name: str, resource_id: Optional[str] = None) -> dict:
        if resource_id:
            url = f"{self.base_url}{self.endpoints[endpoint_name].format(resource_id)}"
        else:
            url = f"{self.base_url}{self.endpoints[endpoint_name]}"
        
        async with httpx.AsyncClient(verify=False, timeout=self.timeout) as client:
            try:
                response = await client.get(url, headers=self.headers)
                response.raise_for_status()
                return response.json()
            except Exception as e:
                return {"error": str(e)}

    async def post(self, endpoint_name: str, param: str) -> dict:
        if endpoint_name == 'search':
            url = f"{self.base_url}{self.endpoints[endpoint_name]}?query_expression={param}"
        else:
            url = f"{self.base_url}{self.endpoints[endpoint_name].format(param)}"
        
        async with httpx.AsyncClient(verify=False, timeout=self.timeout) as client:
            try:
                response = await client.post(url, headers=self.headers)
                response.raise_for_status()
                return response.json()
            except Exception as e:
                return {"error": str(e)}
            
    def create_logsourceid_aql(self, start_time: int, last_updated_time: int) -> str:
        return (
            f"SELECT UTF8(payload), QID, sourceip, destinationip " 
            f"FROM events WHERE logsourceid = 163 AND QID = 1002750255 OR QID = 90250068"
            f"START {start_time} STOP {last_updated_time}"
        )

client = AsyncQRadarClient(URL_BASE, SEC_TOKEN) if URL_BASE and SEC_TOKEN else None

def date_to_timestamp(date_str: str) -> int:
    from datetime import datetime
    
    if 'T' in date_str:
        dt = datetime.fromisoformat(date_str)
    else:
        dt = datetime.fromisoformat(date_str + 'T00:00:00')
    
    timestamp_ms = int(dt.timestamp() * 1000)
    return timestamp_ms

async def get_rule_name(client, rule_id):
    detail_rule_id = await client.get('rules', str(rule_id))
    return detail_rule_id.get('name', 'Unknown')

# ============= 병렬 처리 최적화 =============
async def get_source_ips(client, address_ids):
    if not address_ids:
        return []
    
    async def fetch_ip(addr_id):
        try:
            response = await client.get('source_addresses', str(addr_id))
            if 'source_ip' in response:
                return response['source_ip']
        except Exception as e:
            print(f"ERROR: source_address {addr_id} 조회 실패: {str(e)}")
        return None
    
    tasks = [fetch_ip(addr_id) for addr_id in address_ids]
    results = await asyncio.gather(*tasks)
    
    return [ip for ip in results if ip is not None]

async def get_destination_ips(client, address_ids):
    if not address_ids:
        return []
    
    async def fetch_ip(addr_id):
        try:
            response = await client.get('local_destination_addresses', str(addr_id))
            if 'local_destination_ip' in response:
                return response['local_destination_ip']
        except Exception as e:
            print(f"ERROR: local_destination_address {addr_id} 조회 실패: {str(e)}")
        return None
    
    tasks = [fetch_ip(addr_id) for addr_id in address_ids]
    results = await asyncio.gather(*tasks)
    
    return [ip for ip in results if ip is not None]

async def get_events_with_payload(client, start_time, last_updated_time, decoder):
    aql_query = client.create_logsourceid_aql(start_time, last_updated_time)
    search_response = await client.post('search', aql_query)
    
    if 'error' in search_response:
        return {"error": "검색 요청 실패"}
    
    cursor_id = search_response.get('cursor_id')
    if not cursor_id:
        return {"error": "cursor_id 없음"}
    
    while True:
        status_response = await client.get('search_status', cursor_id)
        if 'error' in status_response:
            return {"error": "상태 확인 실패"}
        if status_response['status'] == 'COMPLETED':
            break
        await asyncio.sleep(0.5)
    
    search_id = status_response['search_id']
    results = await client.get('search_results', search_id)
    
    if 'error' in results:
        return {"error": "결과 조회 실패"}
    
    decoded_events = decoder.export_packet([results])

    return decoded_events

async def integrate_offense_data(client, decoder):
    offenses = await client.get('offenses')
    
    if 'error' in offenses:
        return {"error": offenses}
    
    offense_ids = []
    for offense_item in offenses:
        if any(log_source.get('id') == 163 for log_source in offense_item.get('log_sources', [])):
            offense_ids.append(offense_item['id'])
    
    print(f"INFO: logsource 163이 포함된 offense: {len(offense_ids)}개")
    
    integrated_data_list = []
    
    for idx, offense_id in enumerate(offense_ids, 1):
        try:
            print(f"INFO: [{idx}/{len(offense_ids)}] offense_id {offense_id} 처리 중...")
            
            offense_detail = await client.post('offense_detail', str(offense_id))
            
            if 'error' in offense_detail:
                print(f"WARNING: offense_id {offense_id}: 상세 정보 조회 실패")
                continue
            
            start_time = offense_detail.get('start_time')
            last_updated_time = offense_detail.get('last_updated_time')
            
            if not start_time or not last_updated_time or start_time >= last_updated_time:
                print(f"WARNING: offense_id {offense_id}: 잘못된 시간 범위 - 제외")
                continue
            
            rules_detail = []
            for rule in offense_detail.get('rules', []):
                rule_id = rule['id']
                rule_name = await get_rule_name(client, rule_id)
                
                enhanced_rule = {
                    'id': rule['id'],
                    'type': rule['type'],
                    'name': rule_name
                }
                rules_detail.append(enhanced_rule)
            
            source_address_ids = offense_detail.get('source_address_ids', [])
            source_ips = await get_source_ips(client, source_address_ids)
            print(f"INFO: offense_id {offense_id} - Source IPs: {len(source_ips)}개")
            
            local_destination_address_ids = offense_detail.get('local_destination_address_ids', [])
            destination_ips = await get_destination_ips(client, local_destination_address_ids)
            print(f"INFO: offense_id {offense_id} - Destination IPs: {len(destination_ips)}개")
            
            events_data = await get_events_with_payload(client, start_time, last_updated_time, decoder)
            
            integrated_offense = offense_detail.copy()
            integrated_offense['rules'] = rules_detail
            integrated_offense['source_ips'] = source_ips
            integrated_offense['destination_ips'] = destination_ips
            integrated_offense['events'] = events_data
            
            integrated_data_list.append(integrated_offense)
            print(f"INFO: offense_id {offense_id} 완료")
            
        except Exception as e:
            print(f"ERROR: offense_id {offense_id} 처리 중 오류: {str(e)}")
            continue
    
    return integrated_data_list

async def integrate_offense_data_by_period(client, decoder, start_timestamp, end_timestamp):
    offenses = await client.get('offenses')
    
    if 'error' in offenses:
        return {"error": offenses}
    
    offense_ids = []
    
    for offense_item in offenses:
        if not any(log_source.get('id') == 163 
                   for log_source in offense_item.get('log_sources', [])):
            continue
        
        offense_start = offense_item.get('start_time', 0)
        offense_last = offense_item.get('last_updated_time', 0)
        
        if (start_timestamp <= offense_start <= end_timestamp or
            start_timestamp <= offense_last <= end_timestamp or
            (offense_start <= start_timestamp and offense_last >= end_timestamp)):
            offense_ids.append(offense_item['id'])
    
    print(f"INFO: {len(offense_ids)}개 offense가 기간 내 발견됨")
    
    integrated_data_list = []
    
    for idx, offense_id in enumerate(offense_ids, 1):
        try:
            print(f"INFO: [{idx}/{len(offense_ids)}] offense_id {offense_id} 처리 중...")
            
            offense_detail = await client.post('offense_detail', str(offense_id))
            
            if 'error' in offense_detail:
                continue
            
            rules_detail = []
            for rule in offense_detail.get('rules', []):
                rule_name = await get_rule_name(client, rule['id'])
                rules_detail.append({
                    'id': rule['id'],
                    'type': rule['type'],
                    'name': rule_name
                })
            
            source_ips = await get_source_ips(
                client,
                offense_detail.get('source_address_ids', [])
            )
            destination_ips = await get_destination_ips(
                client,
                offense_detail.get('local_destination_address_ids', [])
            )
            
            offense_start = offense_detail.get('start_time', start_timestamp)
            offense_last = offense_detail.get('last_updated_time', end_timestamp)
            
            actual_start = max(start_timestamp, offense_start)
            actual_end = min(end_timestamp, offense_last)
            
            if actual_start >= actual_end:
                continue
            
            events_data = await get_events_with_payload(
                client,
                actual_start,
                actual_end,
                decoder
            )
            
            integrated_offense = offense_detail.copy()
            integrated_offense['rules'] = rules_detail
            integrated_offense['source_ips'] = source_ips
            integrated_offense['destination_ips'] = destination_ips
            integrated_offense['events'] = events_data
            integrated_offense['queried_period'] = {
                'start': actual_start,
                'end': actual_end
            }
            
            integrated_data_list.append(integrated_offense)
            
        except Exception as e:
            print(f"ERROR: offense_id {offense_id} 처리 중 오류: {str(e)}")
            continue
    
    return integrated_data_list

# ============= 헬퍼 함수 =============
def extract_field(text: str, pattern: str) -> str:
    """정규식으로 필드 추출"""
    match = re.search(pattern, text)
    return match.group(1) if match else "-"

def generate_virustotal_section(vt_results: List[Dict]) -> str:
    """VirusTotal HTML 섹션 생성"""
    
    total = len(vt_results)
    malicious = 0
    suspicious = 0
    clean = 0
    
    for r in vt_results:
        try:
            stats = r['data']['attributes']['last_analysis_stats']
            if stats.get('malicious', 0) > 0:
                malicious += 1
            elif stats.get('suspicious', 0) > 0:
                suspicious += 1
            else:
                clean += 1
        except:
            pass
    
    html = f'''
        <div class="section">
            <h2>VirusTotal 악성코드 분석</h2>
            
            <div class="findings-box" style="margin-bottom: 6px;">
                <h3>VirusTotal 분석 요약</h3>
                <p><strong>총 검사:</strong> {total}개</p>
                <p><strong>악성:</strong> <span style="color: #8b0000; font-weight: 600;">{malicious}개</span> | 
                   <strong>의심:</strong> <span style="color: #a0522d; font-weight: 600;">{suspicious}개</span> | 
                   <strong>안전:</strong> <span style="color: #2f4f4f; font-weight: 600;">{clean}개</span></p>
            </div>


            <table class="main-table">
                <thead>
                    <tr>
                        <th style="width: 8%;">Offense</th>
                        <th style="width: 18%;">해시값</th>
                        <th style="width: 12%;">백신 탐지명</th>
                        <th style="width: 8%;">판정</th>
                        <th style="width: 8%;">탐지율</th>
                        <th style="width: 20%;">VirusTotal 탐지명</th>
                        <th style="width: 26%;">주요 탐지 엔진</th>
                    </tr>
                </thead>
                <tbody>

'''
    
    for result in vt_results:
        try:
            hash_val = result.get('hash', '')
            offense_id = result.get('offense_id', '-')
            qradar_virus_name = result.get('virus_name', '-')
            
            attrs = result['data']['attributes']
            
            stats = attrs['last_analysis_stats']
            mal_count = stats.get('malicious', 0)
            total_engines = sum(stats.values())
            
            if mal_count > 0:
                verdict = '<span class="status-badge status-open">악성</span>'
            elif stats.get('suspicious', 0) > 0:
                verdict = '<span class="priority-badge medium">의심</span>'
            else:
                verdict = '<span class="status-badge status-closed">안전</span>'
            
            results_dict = attrs.get('last_analysis_results', {})
            detection_name = "-"
            engines = []
            
            for engine, data in results_dict.items():
                if data.get('category') in ['malicious', 'suspicious']:
                    if detection_name == "-":
                        detection_name = data.get('result', '-')
                    engines.append(engine)
            
            engine_str = ', '.join(engines[:3])
            if len(engines) > 3:
                engine_str += f' 외 {len(engines)-3}개'
            
            display_hash = hash_val
            
            html += f'''
                    <tr>
                        <td style="text-align: center; font-weight: 400;">{offense_id}</td>
                        <td><code style="word-break: break-all;">{display_hash}</code></td>
                        <td>{qradar_virus_name}</td>
                        <td style="text-align: center;">{verdict}</td>
                        <td style="text-align: center;">{mal_count}/{total_engines}</td>
                        <td>{detection_name}</td>
                        <td>{engine_str if engine_str else '-'}</td>
                    </tr>
'''
        except Exception as e:
            html += f'<tr><td colspan="7">해시 처리 오류: {str(e)}</td></tr>'
    
    html += '''
                </tbody>
            </table>
        </div>
'''
    
    return html

# ============= MCP Tools =============
@mcp.tool()
async def qradar_api_test() -> str:
    """QRadar API 연결 테스트"""
    if not client:
        return json.dumps({"error": "QRadar 클라이언트가 설정되지 않았습니다."}, indent=2)
    response = await client.get('about')
    return json.dumps(response, indent=2)

@mcp.tool()
async def qradar_get_offenses_summary() -> str:
    """QRadar offense 요약 정보만 빠르게 조회"""
    if not client:
        return json.dumps({"error": "QRadar 클라이언트가 설정되지 않았습니다."}, indent=2)
    
    try:
        offenses = await client.get('offenses')
        if 'error' in offenses:
            return json.dumps({"error": offenses}, indent=2)
        
        filtered_offenses = []
        for offense in offenses:
            if any(log_source.get('id') == 163 
                   for log_source in offense.get('log_sources', [])):
                filtered_offenses.append({
                    'id': offense.get('id'),
                    'severity': offense.get('severity'),
                    'magnitude': offense.get('magnitude'),
                    'status': offense.get('status'),
                    'event_count': offense.get('event_count'),
                    'description': offense.get('description', '')[:100]
                })
        
        summary = {
            "total_count": len(filtered_offenses),
            "offense_ids": [o['id'] for o in filtered_offenses],
            "offenses": filtered_offenses
        }
        
        return json.dumps(summary, indent=2, ensure_ascii=False)
        
    except Exception as e:
        return json.dumps({"error": f"요약 조회 중 오류: {str(e)}"}, indent=2)

@mcp.tool()
async def qradar_collect_and_save(output_dir: str = DEFAULT_OUTPUT_DIR) -> str:
    """QRadar에서 전체 offense 데이터를 수집하여 파일로 저장"""
    if not client:
        return json.dumps({
            "error": "QRadar 클라이언트가 설정되지 않았습니다."
        }, indent=2)
    
    try:
        os.makedirs(output_dir, exist_ok=True)
        
        print("INFO: QRadar에서 전체 offense 데이터 수집 중...")
        
        decoder = HexDecoder()
        integrated_data_list = await integrate_offense_data(client, decoder)
        
        if isinstance(integrated_data_list, dict) and 'error' in integrated_data_list:
            return json.dumps(integrated_data_list, indent=2)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"qradar_offenses_{timestamp}.json"
        filepath = os.path.join(output_dir, filename)
        
        result = {
            "collected_at": timestamp,
            "total_offenses": len(integrated_data_list),
            "logsource_id": 163,
            "data": integrated_data_list
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        
        file_size = os.path.getsize(filepath)
        
        print(f"INFO: 저장 완료 - {len(integrated_data_list)}개 offense, "
              f"{file_size / (1024*1024):.2f} MB")
        
        return json.dumps({
            "status": "success",
            "message": "데이터 수집 및 저장 완료",
            "filepath": filepath,
            "total_offenses": len(integrated_data_list),
            "file_size_kb": round(file_size / 1024, 2),
            "file_size_mb": round(file_size / (1024 * 1024), 2),
            "collected_at": timestamp
        }, indent=2)
        
    except Exception as e:
        import traceback
        return json.dumps({
            "error": f"데이터 수집 중 오류: {str(e)}",
            "traceback": traceback.format_exc()
        }, indent=2)

@mcp.tool()
async def qradar_collect_by_period(
    start_date: str,
    end_date: str,
    output_dir: str = DEFAULT_OUTPUT_DIR
) -> str:
    """지정한 기간의 QRadar offense 데이터 수집"""
    if not client:
        return json.dumps({
            "error": "QRadar 클라이언트가 설정되지 않았습니다."
        }, indent=2)
    
    try:
        start_timestamp = date_to_timestamp(start_date)
        
        if 'T' not in end_date:
            end_date = end_date + 'T23:59:59'
        end_timestamp = date_to_timestamp(end_date)
        
        print(f"INFO: 기간 조회 - {start_date} ~ {end_date}")
        
        decoder = HexDecoder()
        
        integrated_data_list = await integrate_offense_data_by_period(
            client,
            decoder,
            start_timestamp,
            end_timestamp
        )
        
        if isinstance(integrated_data_list, dict) and 'error' in integrated_data_list:
            return json.dumps(integrated_data_list, indent=2)
        
        os.makedirs(output_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_start_date = start_date.replace(':', '-').replace('T', '_')
        safe_end_date = end_date.replace(':', '-').replace('T', '_')

        filename = f"qradar_offenses_{safe_start_date}_to_{safe_end_date}_{timestamp}.json"
        filepath = os.path.join(output_dir, filename)
        
        result = {
            "collected_at": timestamp,
            "period": {
                "start_date": start_date,
                "end_date": end_date,
                "start_timestamp": start_timestamp,
                "end_timestamp": end_timestamp
            },
            "total_offenses": len(integrated_data_list),
            "logsource_id": 163,
            "data": integrated_data_list
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        
        file_size = os.path.getsize(filepath)
        
        print(f"INFO: 저장 완료 - {len(integrated_data_list)}개 offense")
        
        return json.dumps({
            "status": "success",
            "message": f"{start_date} ~ {end_date} 기간 데이터 수집 완료",
            "period": {
                "start": start_date,
                "end": end_date,
                "start_timestamp": start_timestamp,
                "end_timestamp": end_timestamp
            },
            "filepath": filepath,
            "total_offenses": len(integrated_data_list),
            "file_size_mb": round(file_size / (1024 * 1024), 2)
        }, indent=2)
        
    except Exception as e:
        import traceback
        return json.dumps({
            "error": f"데이터 수집 중 오류: {str(e)}",
            "traceback": traceback.format_exc()
        }, indent=2)

@mcp.tool()
async def qradar_prepare_event_matching(
    filepath: str,
    max_offenses: int = 8
) -> str:
    """
    Gemini가 패킷 내용을 분석해 공격 유형과 패턴을 자동 판단하도록 데이터 준비
    
    Args:
        filepath: QRadar JSON 파일 경로
        max_offenses: 처리할 최대 offense 개수
    """
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        all_offenses = data.get('data', [])
        
        # Gemini 분석용 데이터 준비
        analysis_request = []
        
        for offense in all_offenses[:max_offenses]:
            offense_id = offense.get('id')
            rules = offense.get('rules', [])
            events = offense.get('events', [])
            
            if not events:
                continue
            
            # QRadar rule은 참고용으로만
            qradar_rule = rules[0].get('name', 'Unknown') if rules else 'Unknown'
            
            # 이벤트 샘플 준비 (최대 5개, 500자 제한)
            event_samples = []
            for i, event in enumerate(events[:5]):
                event_str = str(event)
                if len(event_str) > 500:
                    event_str = event_str[:500] + "..."
                event_samples.append(f"Event {i+1}: {event_str}")
            
            analysis_request.append({
                "offense_id": offense_id,
                "qradar_rule_reference": qradar_rule,
                "events": event_samples
            })
        
        # Gemini 프롬프트 생성
        gemini_prompt = f"""당신은 네트워크 보안 전문가입니다. 
다음 QRadar offense의 이벤트 패킷을 분석하여 실제 공격 유형을 판단하고 핵심 패턴을 추출하세요.

**중요**: QRadar rule은 참고만 하고, 실제 패킷 내용을 보고 직접 판단하세요.

**분석 방법**:
1. 각 offense의 이벤트 패킷 내용을 분석
2. 패킷에서 실제 공격 특징을 찾아서 공격 유형 판단:
   - SQL Injection: SQL 쿼리, OR '1'='1, UNION SELECT 등
   - XSS: <script>, alert(), javascript: 등
   - ICMP Flooding: ICMP 패킷, packet_hex, flooding 패턴
   - Directory Traversal: ../, %2e%2e, 경로 조작
   - Virus/Malware: VIRUS_Hash, VIRUS_NAME, 바이러스 탐지 로그
   - DDoS: 대량 패킷, flooding 패턴
   - Command Injection: ; ls, && cat, | whoami 등
   - 기타 새로운 공격 패턴도 패킷 분석으로 판단
3. 공격 패턴 추출 (150자 이내):
   - SQL Injection → 실제 주입된 쿼리
   - XSS → 삽입된 스크립트
   - Virus → 해시값 또는 바이러스명
   - ICMP → "(ICMP flooding 패킷)" 또는 패킷 정보 또는 빈 패킷

**응답 형식** (JSON 배열만 반환, 다른 설명 금지):
[
  {{
    "offense_id": 88,
    "attack_type": "SQL Injection",
    "attack_pattern": "GET /admin.php?id=1' OR '1'='1",
    "confidence": "high"
  }},
  {{
    "offense_id": 87,
    "attack_type": "Malware Detection",
    "attack_pattern": "7D49E26BEC17DED435B5CE94D84F1991",
    "confidence": "high"
  }}
]

**분석할 데이터**:
{json.dumps(analysis_request, ensure_ascii=False, indent=2)}

주의사항:
- QRadar rule은 무시하고 패킷 내용만으로 판단
- 확신이 없으면 "Unknown Attack"으로 표시하고 confidence를 "low"로 설정
- 반드시 JSON 배열만 반환
"""
        
        return json.dumps({
            "status": "ready_for_gemini",
            "message": "Gemini에게 다음 프롬프트를 전달하세요. Gemini가 패킷을 분석해 공격 유형을 자동 판단합니다.",
            "total_offenses": len(analysis_request),
            "gemini_prompt": gemini_prompt,
            "filepath": filepath,
            "next_step": "Gemini의 JSON 응답을 받으면 qradar_generate_report_with_virustotal() 도구를 호출하세요"
        }, indent=2, ensure_ascii=False)
        
    except Exception as e:
        import traceback
        return json.dumps({
            "error": f"분석 데이터 준비 중 오류: {str(e)}",
            "traceback": traceback.format_exc()
        }, indent=2)

@mcp.tool()
async def qradar_generate_report_with_virustotal(
    filepath: str,
    gemini_analysis_result: Optional[List[Dict]] = None
) -> str:
    """
    QRadar 데이터로 HTML 보고서 생성 (선택적으로 Gemini AI 분석 결과 포함)
    
    Args:
        filepath: QRadar JSON 파일 경로
        gemini_analysis_result: (선택) Gemini AI 분석 결과
    """
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        all_offenses = data.get('data', [])
        collected_at = data.get('collected_at', 'N/A')

        # gemini 결과
        gemini_json = json.dumps(gemini_analysis_result, ensure_ascii=False) if gemini_analysis_result else "null"

        
        # HTML 생성 (JavaScript 데이터 포함)
        json_data = json.dumps(all_offenses, ensure_ascii=False, indent=2)
        
        fixed_collected_time = datetime.now().strftime('%Y.%m.%d - %H:%M:%S')
        html_content = f'''<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>QRadar Offense 분석 보고서</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Malgun Gothic', '맑은 고딕', 'Segoe UI', Arial, sans-serif; background-color: #f0f0f0; padding: 10px; display: flex; justify-content: center; align-items: flex-start; min-height: 100vh; }}
        .container {{ width: 210mm; min-height: 297mm; background: white; padding: 15mm; box-shadow: 0 2px 10px rgba(0,0,0,0.1); border-radius: 3px; }}
        .header {{ text-align: center; background: #34495e; color: white; padding: 8px; border-radius: 3px; margin-bottom: 8px; }}
        .header h1 {{ font-size: 14px; font-weight: 600; margin-bottom: 2px; }}
        .header .subtitle {{ font-size: 10px; opacity: 0.9; }}
        .summary-cards {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 6px; margin-bottom: 8px; }}
        .summary-card {{ background: #ecf0f1; padding: 4px; border-radius: 3px; border: 1px solid #95a5a6; text-align: center; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
        .summary-card strong {{ display: block; color: #2c3e50; font-size: 7px; font-weight: 600; margin-bottom: 1px; text-transform: uppercase; }}
        .summary-card span {{ color: #34495e; font-weight: 600; font-size: 8px; }}
        .findings-box {{ background: #f5f5f5; border: 1px solid #808080; border-radius: 3px; padding: 6px; margin-bottom: 6px; }}
        .findings-box h3 {{ color: #2c3e50; font-size: 9px; margin-bottom: 3px; font-weight: 600; }}
        .findings-box p {{ color: #34495e; margin-bottom: 1px; font-size: 7px; }}
        .section {{ margin-bottom: 6px; }}
        .section:last-child {{ margin-bottom: 0; }}
        .section h2 {{ font-size: 10px; font-weight: 600; color: #2c3e50; margin-bottom: 3px; padding: 4px 6px; border-bottom: 1px solid #808080; background: #f5f5f5; border-radius: 3px 3px 0 0; }}
        .stats-section {{ display: grid; grid-template-columns: 1fr 1fr; gap: 6px; margin-bottom: 6px; }}
        .stats-table {{ width: 100%; border-collapse: collapse; font-size: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); border-radius: 3px; overflow: hidden; }}
        .main-table {{ width: 100%; border-collapse: collapse; font-size: 7px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); border-radius: 3px; overflow: hidden; table-layout: fixed; }}
        .stats-table th, .stats-table td {{ border: 1px solid #95a5a6; padding: 3px; text-align: center; }}
        .main-table th, .main-table td {{ border: 1px solid #95a5a6; padding: 2px; text-align: left; vertical-align: top; word-wrap: break-word; overflow-wrap: break-word; line-height: 1.1; }}
        .stats-table th, .main-table th {{ background: #34495e; color: white; font-weight: 600; font-size: 8px; text-align: center; }}
        .main-table th {{ font-size: 7px; }}
        .stats-table tr, .main-table tr {{ background-color: white; }}
        .main-table tr:hover {{ background-color: #e9ecef; }}
        .severity-badge {{ display: inline-block; padding: 1px 4px; border-radius: 2px; font-weight: 600; font-size: 6px; text-align: center; color: white; min-width: 15px; }}
        .severity-8 {{ background-color: #8b0000; }}
        .severity-7 {{ background-color: #a0522d; }}
        .severity-6 {{ background-color: #696969; }}
        .severity-5 {{ background-color: #556b2f; }}
        .severity-4 {{ background-color: #4682b4; }}
        .severity-3 {{ background-color: #708090; }}
        .severity-2 {{ background-color: #808080; }}
        .severity-1 {{ background-color: #2f4f4f; }}
        .status-badge {{ display: inline-block; padding: 1px 4px; border-radius: 2px; font-weight: 600; font-size: 6px; text-align: center; color: white; }}
        .status-open {{ background-color: #8b0000; }}
        .status-closed {{ background-color: #2f4f4f; }}
        .priority-badge {{ padding: 1px 4px; border-radius: 2px; font-size: 6px; font-weight: 600; color: white; }}
        .priority-badge.high {{ background-color: #8b0000; }}
        .priority-badge.medium {{ background-color: #a0522d; }}
        .priority-badge.low {{ background-color: #2f4f4f; }}
        code {{ font-size: 6px; word-break: break-all; white-space: normal; background-color: #f8f9fa; padding: 1px 2px; border-radius: 1px; }}
        .summary-row {{ background-color: #f8f9fa !important; border: 1px solid #95a5a6; }}
        .summary-row td {{ text-align: center; font-weight: 600; color: #2c3e50; font-size: 7px; }}
        @media print {{ @page {{ size: A4; margin: 8mm; }} body {{ background: white; padding: 0; }} .container {{ width: 100%; min-height: auto; padding: 5mm; box-shadow: none; border-radius: 0; }} .header {{ margin: -8mm -8mm 6mm -8mm; border-radius: 0; padding: 6px; }} }}
        .ai-label {{ background-color: #4682b4; color: white; padding: 1px 3px; border-radius: 2px; font-size: 5px; margin-left: 3px; }}
     </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>QRadar Offense 분석 보고서</h1>
            <div class="subtitle">보안 위협 분석 및 대응 방안</div>
        </div>
        
        <div class="summary-cards">
            <div class="summary-card"><strong>수집 시간</strong><span id="collectedAt">-</span></div>
            <div class="summary-card"><strong>총 OFFENSE</strong><span id="totalOffenses">-</span></div>
            <div class="summary-card"><strong>LOGSOURCE ID</strong><span id="logSourceId">-</span></div>
            <div class="summary-card"><strong>총 이벤트</strong><span id="totalEvents">-</span></div>
            <div class="summary-card"><strong>분석 기간</strong><span id="pastDataRange">-</span></div>
        </div>
        
        <div class="findings-box">
            <h3>주요 발견사항</h3>
            <p><strong>주요 공격 유형:</strong> <span id="mainAttackTypes">-</span></p>
            <p><strong>주요 공격자 IP:</strong> <span id="mainAttackerIPs">-</span></p>
            <p><strong>대상 서버:</strong> <span id="targetServers">-</span></p>
            <p><strong>심각도 분포:</strong> <span id="severityDistribution">-</span></p>
        </div>
        
        <div class="stats-section">
            <div class="section">
                <table class="stats-table">
                    <thead><tr><th>심각도</th><th>건수</th></tr></thead>
                    <tbody id="severityStatsBody"></tbody>
                </table>
            </div>
            <div class="section">
                <table class="stats-table">
                    <thead><tr><th>주요 공격유형</th><th>상태</th></tr></thead>
                    <tbody id="attackTypeStatsBody"></tbody>
                </table>
            </div>
        </div>
        
        <div class="section">
            <h2>Offense 상세 정보</h2>
            <table class="main-table">
                <thead>
                    <tr>
                        <th style="width: 8%;">ID</th>
                        <th style="width: 8%;">심각도</th>
                        <th style="width: 8%;">이벤트</th>
                        <th style="width: 10%;">상태</th>
                        <th style="width: 18%;">출발지 IP</th>
                        <th style="width: 18%;">목적지 IP</th>
                        <th style="width: 30%;">설명</th>
                    </tr>
                </thead>
                <tbody id="offensesTableBody"></tbody>
            </table>
        </div>
        
        <div class="section">
            <h2>탐지 규칙</h2>
            <table class="main-table">
                <thead>
                    <tr>
                        <th style="width: 10%;">Offense</th>
                        <th style="width: 25%;">규칙명</th>
                        <th style="width: 15%;">규칙 ID</th>
                        <th style="width: 15%;">타입</th>
                        <th style="width: 35%;">설명</th>
                    </tr>
                </thead>
                <tbody id="rulesTableBody"></tbody>
            </table>
        </div>
        
        <div class="section">
            <h2>주요 이벤트 샘플</h2>
            <table class="main-table">
                <thead>
                    <tr>
                        <th style="width: 10%;">Offense</th>
                        <th style="width: 15%;">공격 유형</th>
                        <th style="width: 35%;">공격 패턴</th>
                    </tr>
                </thead>
                <tbody id="eventSamplesTableBody"></tbody>
            </table>
        </div>
        
        <div id="virustotal-placeholder"></div>
        
        <div class="section">
            <h2>권고 조치 방안</h2>
            <table class="main-table">
                <thead>
                    <tr>
                        <th style="width: 12%;">우선순위</th>
                        <th style="width: 20%;">취약점/위협</th>
                        <th style="width: 25%;">대상/패턴</th>
                        <th style="width: 28%;">조치방법</th>
                        <th style="width: 15%;">목적</th>
                    </tr>
                </thead>
                <tbody id="recommendationsTableBody"></tbody>
            </table>
        </div>
    </div>
    
    <script>
        const offenseData = {json_data};
        const geminiAnalysis = {gemini_json};
        const collectedTime = "{fixed_collected_time}";
        
        function loadReportData(data) {{
            document.getElementById('collectedAt').textContent = collectedTime;
            document.getElementById('totalOffenses').textContent = data.length;
            
            if (data.length > 0 && data[0].log_sources && data[0].log_sources.length > 0) {{
                document.getElementById('logSourceId').textContent = data[0].log_sources[0].id;
            }} else {{
                document.getElementById('logSourceId').textContent = '163';
            }}
            
            const totalEvents = data.reduce((sum, o) => sum + (o.event_count || 0), 0);
            document.getElementById('totalEvents').textContent = totalEvents.toLocaleString();
            
            if (data.length > 0) {{
                const dates = data.map(o => {{
                    const qp = o.queried_period;
                    if (qp && qp.start && qp.end) {{
                        return {{ start: qp.start, end: qp.end }};
                    }}
                    return {{
                        start: o.start_time || o.first_persisted_time || o.last_persisted_time,
                        end: o.last_updated_time || o.last_persisted_time
                    }};
                }});
                
                const startDate = new Date(Math.min(...dates.map(d => d.start)));
                const endDate = new Date(Math.max(...dates.map(d => d.end)));
                document.getElementById('pastDataRange').textContent = 
                    startDate.toLocaleDateString('ko-KR') + ' ~ ' + endDate.toLocaleDateString('ko-KR');
            }}
            
            updateSummaryInfo(data);
            updateSeverityStats(data);
            updateAttackTypeStats(data);
            updateOffensesTable(data);
            updateRulesTable(data);
            updateEventSamplesTable(data);
            updateRecommendationsTable(data);
        }}
        
        function updateSummaryInfo(data) {{
            const attackTypes = new Set();
            data.forEach(o => {{
                if (o.rules) o.rules.forEach(r => {{
                    if (r.name) attackTypes.add(r.name);
                }});
            }});
            document.getElementById('mainAttackTypes').textContent = 
                Array.from(attackTypes).slice(0, 3).join(', ') || '-';
            
            const sourceIPs = new Set();
            data.forEach(o => {{
                if (o.source_ips) o.source_ips.forEach(ip => {{
                    if (ip) sourceIPs.add(ip);
                }});
            }});
            document.getElementById('mainAttackerIPs').textContent = 
                Array.from(sourceIPs).slice(0, 2).join(', ') || '-';
            
            const destIPs = new Set();
            data.forEach(o => {{
                if (o.destination_ips) o.destination_ips.forEach(ip => {{
                    if (ip) destIPs.add(ip);
                }});
            }});
            document.getElementById('targetServers').textContent = 
                Array.from(destIPs).join(', ') || '-';
            
            const severityCount = {{}};
            data.forEach(o => {{
                const sev = o.severity || o.magnitude || 1;
                severityCount[sev] = (severityCount[sev] || 0) + 1;
            }});
            const severityDist = Object.entries(severityCount)
                .sort((a, b) => b[0] - a[0])
                .map(([s, c]) => `Severity ${{s}} (${{c}})`)
                .join(', ');
            document.getElementById('severityDistribution').textContent = severityDist || '-';
        }}
        
        function updateSeverityStats(data) {{
            const tbody = document.getElementById('severityStatsBody');
            tbody.innerHTML = '';
            
            const severityCount = {{}};
            data.forEach(o => {{
                const sev = o.severity || o.magnitude || 1;
                severityCount[sev] = (severityCount[sev] || 0) + 1;
            }});
            
            Object.keys(severityCount).sort((a, b) => b - a).forEach(sev => {{
                const row = `<tr>
                    <td><span class="severity-badge severity-${{sev}}">${{sev}}</span></td>
                    <td>${{severityCount[sev]}}</td>
                </tr>`;
                tbody.innerHTML += row;
            }});
        }}
        
        function updateAttackTypeStats(data) {{
            const tbody = document.getElementById('attackTypeStatsBody');
            tbody.innerHTML = '';
            
            const attackTypeCount = {{}};
            const attackTypeStatus = {{}};
            
            data.forEach(o => {{
                if (o.rules) o.rules.forEach(r => {{
                    if (r.name) {{
                        attackTypeCount[r.name] = (attackTypeCount[r.name] || 0) + 1;
                        if (!attackTypeStatus[r.name]) attackTypeStatus[r.name] = {{ open: 0, closed: 0 }};
                        
                        const status = o.status || (o.inactive ? 'CLOSED' : 'OPEN');
                        if (status === 'OPEN') attackTypeStatus[r.name].open++;
                        else attackTypeStatus[r.name].closed++;
                    }}
                }});
            }});
            
            Object.entries(attackTypeCount)
                .sort((a, b) => b[1] - a[1])
                .slice(0, 4)
                .forEach(([type, count]) => {{
                    const status = attackTypeStatus[type];
                    const statusText = status.open > 0 ? `OPEN (${{status.open}})` : `CLOSED (${{status.closed}})`;
                    const row = `<tr><td>${{type}}</td><td>${{statusText}}</td></tr>`;
                    tbody.innerHTML += row;
                }});
        }}
        
        function updateOffensesTable(data) {{
            const tbody = document.getElementById('offensesTableBody');
            tbody.innerHTML = '';
            
            const maxRows = Math.min(data.length, 15);
            
            data.slice(0, maxRows).forEach(o => {{
                const sourceIPs = o.source_ips && o.source_ips.length > 0 ? 
                    o.source_ips.slice(0, 2).join(', ') : '-';
                const destIPs = o.destination_ips && o.destination_ips.length > 0 ? 
                    o.destination_ips.slice(0, 2).join(', ') : '-';
                const status = o.status || (o.inactive ? 'CLOSED' : 'OPEN');
                const statusClass = status === 'OPEN' ? 'status-open' : 'status-closed';
                const severity = o.severity || o.magnitude || 1;
                
                const row = `<tr>
                    <td style="text-align: center; font-weight: 400;">${{o.id}}</td>
                    <td style="text-align: center;"><span class="severity-badge severity-${{severity}}">${{severity}}</span></td>
                    <td style="text-align: center;">${{o.event_count || 0}}</td>
                    <td style="text-align: center;"><span class="status-badge ${{statusClass}}">${{status}}</span></td>
                    <td>${{sourceIPs}}</td>
                    <td>${{destIPs}}</td>
                    <td>${{o.description || '-'}}</td>
                </tr>`;
                tbody.innerHTML += row;
            }});
            
            if (data.length > maxRows) {{
                tbody.innerHTML += `<tr class="summary-row">
                    <td colspan="7">총 ${{data.length}}개 Offense 중 상위 ${{maxRows}}개 표시</td>
                </tr>`;
            }}
        }}
        
        function updateRulesTable(data) {{
            const tbody = document.getElementById('rulesTableBody');
            tbody.innerHTML = '';
            
            let ruleCount = 0;
            const maxRules = 12;
            
            data.forEach(o => {{
                if (o.rules && o.rules.length > 0 && ruleCount < maxRules) {{
                    o.rules.forEach(r => {{
                        if (ruleCount >= maxRules) return;
                        
                        const row = `<tr>
                            <td style="text-align: center; font-weight: 400;">${{o.id}}</td>
                            <td>${{r.name || '-'}}</td>
                            <td style="text-align: center;">${{r.id || '-'}}</td>
                            <td style="text-align: center;">${{r.type || '-'}}</td>
                            <td>${{r.name || '-'}}</td>
                        </tr>`;
                        tbody.innerHTML += row;
                        ruleCount++;
                    }});
                }}
            }});
        }}
        
        function updateEventSamplesTable(data) {{
            const tbody = document.getElementById('eventSamplesTableBody');
            tbody.innerHTML = '';
            
            const maxSamples = Math.min(data.length, 8);
            
            data.slice(0, maxSamples).forEach(o => {{
                if (!o.events || o.events.length === 0) return;
                
                const sample = o.events[0];
                let attackType = '-';
                let attackPattern = '-';
                let isAI = false;
                
                //  1. Gemini 결과가 있으면 우선 사용
                if (geminiAnalysis && Array.isArray(geminiAnalysis)) {{
                    const aiResult = geminiAnalysis.find(a => a.offense_id === o.id);
                    if (aiResult) {{
                        attackType = aiResult.attack_type;
                        attackPattern = aiResult.attack_pattern;
                        isAI = true;
                    }}
                }}
                
                // 2. Gemini 결과 없으면 기존 로직
                if (!isAI) {{
                    attackType = o.rules && o.rules.length > 0 ? o.rules[0].name : '-';
                    
                    if (typeof sample === 'string') {{
                        const hashMatch = sample.match(/VIRUS_Hash:\\s*\\"?([A-F0-9]+)\\"?/i);
                        
                        if (hashMatch && hashMatch[1]) {{
                            attackPattern = hashMatch[1];
                        }} else if (sample.includes('packet_len=0')) {{
                            attackPattern = '(빈 패킷)';
                        }} else {{
                            attackPattern = sample.length > 150 ? sample.substring(0, 150) + '...' : sample;
                        }}
                    }}
                }}
                
                // AI 라벨 추가
                const aiLabel = isAI ? '<span class="ai-label">AI</span>' : '';
                
                const row = `<tr>
                    <td style="text-align: center; font-weight: 400;">${{o.id}}</td>
                    <td>${{attackType}}${{aiLabel}}</td>
                    <td><code style="word-break: break-all;">${{attackPattern}}</code></td>
                </tr>`;
                tbody.innerHTML += row;
            }});
        }}
        
        function updateRecommendationsTable(data) {{
            const tbody = document.getElementById('recommendationsTableBody');
            tbody.innerHTML = '';
            
            const recommendations = [];
            
            const attackTypes = new Set();
            data.forEach(o => {{
                if (o.rules) o.rules.forEach(r => {{
                    if (r.name && r.name !== 'Unknown') attackTypes.add(r.name);
                }});
            }});
            
            const sourceIPs = new Set();
            data.forEach(o => {{
                if (o.source_ips) o.source_ips.forEach(ip => {{
                    if (ip) sourceIPs.add(ip);
                }});
            }});
            
            if (sourceIPs.size > 0) {{
                recommendations.push({{
                    priority: 'high',
                    priorityText: '긴급',
                    vulnerability: '공격자 IP 차단',
                    target: Array.from(sourceIPs).slice(0, 2).join(', '),
                    action: '방화벽 또는 WAF에서 즉시 차단',
                    purpose: '추가 공격 방지'
                }});
            }}
            
            let recCount = 0;
            attackTypes.forEach(attackType => {{
                if (recCount >= 3) return;
                
                let priority = 'medium';
                let priorityText = '중요';
                let action = '';
                let purpose = '';
                
                if (attackType.includes('XSS')) {{
                    priority = 'high';
                    priorityText = '긴급';
                    action = 'Output Encoding, CSP 적용';
                    purpose = '악성 스크립트 방지';
                }} else if (attackType.includes('Directory Traversal') || attackType.includes('file=')) {{
                    priority = 'high';
                    priorityText = '긴급';
                    action = '파일 경로 처리 로직 수정';
                    purpose = '비공개 파일 접근 차단';
                }} else if (attackType.includes('SQL')) {{
                    priority = 'high';
                    priorityText = '긴급';
                    action = '파라미터화된 쿼리 사용';
                    purpose = 'DB 조작 방지';
                }} else {{
                    action = '해당 공격 유형 보안 강화';
                    purpose = '공격 방지';
                }}
                
                recommendations.push({{
                    priority,
                    priorityText,
                    vulnerability: attackType,
                    target: attackType,
                    action,
                    purpose
                }});
                recCount++;
            }});
            
            recommendations.push({{
                priority: 'low',
                priorityText: '일반',
                vulnerability: '지속적인 모니터링',
                target: 'QRadar 및 서버 로그',
                action: '정기적인 로그 검토, 패턴 분석',
                purpose: '재발 방지'
            }});
            
            recommendations.forEach(rec => {{
                const row = `<tr>
                    <td style="text-align: center;"><span class="priority-badge ${{rec.priority}}">${{rec.priorityText}}</span></td>
                    <td>${{rec.vulnerability}}</td>
                    <td><code>${{rec.target}}</code></td>
                    <td>${{rec.action}}</td>
                    <td>${{rec.purpose}}</td>
                </tr>`;
                tbody.innerHTML += row;
            }});
            
            tbody.innerHTML += `<tr class="summary-row">
                <td colspan="5">${{recommendations.length}} 건의 권고 조치 방안 제시</td>
            </tr>`;
        }}
        
        document.addEventListener('DOMContentLoaded', function() {{
            loadReportData(offenseData);
        }});
    </script>
</body>
</html>'''
        
        # HTML 파일 저장
        suffix = '_ai_report' if gemini_analysis_result else '_report'
        html_filepath = filepath.replace('.json', f'{suffix}.html')
        with open(html_filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        # VIRUS_Hash 추출
        virus_hashes = []
        hash_details = []
        
        for offense in all_offenses:
            offense_id = offense.get('id')
            events = offense.get('events', [])
            
            for event in events:
                if not isinstance(event, str):
                    continue
                
                hash_match = re.search(r'VIRUS_Hash:\s*"([A-Fa-f0-9]{32,64})"', event)
                if hash_match:
                    hash_value = hash_match.group(1).upper()
                    
                    if hash_value not in virus_hashes:
                        virus_hashes.append(hash_value)
                        
                        virus_name = extract_field(event, r'VIRUS_NAME:\s*"([^"]+)"')
                        virus_type = extract_field(event, r'VIRUS_TYPE:\s*"([^"]+)"')
                        
                        hash_details.append({
                            "hash": hash_value,
                            "offense_id": offense_id,
                            "virus_name": virus_name,
                            "virus_type": virus_type
                        })

        # 메시지에 AI 여부 표시
        ai_status = f"(Gemini AI 분석 {len(gemini_analysis_result)}개 포함)" if gemini_analysis_result else ""
       
        if virus_hashes:
            next_step_message = f"""
1차 보고서 생성 완료: {html_filepath}

바이러스 해시 {len(virus_hashes)}개 발견:
{json.dumps(hash_details, indent=2, ensure_ascii=False)}

다음 단계:
각 해시를 VirusTotal에서 조회한 후, 
qradar_update_html_with_virustotal() 도구를 사용해서 
HTML에 VirusTotal 섹션을 추가하세요.

예시 명령:
"위 해시들을 VirusTotal에서 조회하고 보고서에 추가해줘"
"""
        else:
            next_step_message = f"""
보고서 생성 완료: {html_filepath}
VIRUS_Hash가 발견되지 않았습니다.
"""
        
        return json.dumps({
            "status": "success",
            "html_filepath": html_filepath,
            "analysis_type": "AI" if gemini_analysis_result else "Basic",
            "ai_analyzed_count": len(gemini_analysis_result) if gemini_analysis_result else 0,
            "virus_hashes": virus_hashes,
            "hash_details": hash_details,
            "total_hashes": len(virus_hashes),
            "message": next_step_message
        }, indent=2, ensure_ascii=False)
        
    except Exception as e:
        import traceback
        return json.dumps({
            "error": f"보고서 생성 중 오류: {str(e)}",
            "traceback": traceback.format_exc()
        }, indent=2)

@mcp.tool()
async def qradar_update_html_with_virustotal(
    html_filepath: str,
    virustotal_results: List[Dict]
) -> str:
    """
    HTML 보고서에 VirusTotal 섹션 추가
    
    gemini가 VirusTotal 조회 완료 후 이 도구 호출
    
    Args:
        html_filepath: HTML 보고서 파일 경로
        virustotal_results: VirusTotal API 응답 리스트
            [
                {
                    "hash": "7D49E26...",
                    "offense_id": 79,
                    "virus_name": "Spyware.OnlineGames-GLG",
                    "data": {
                        "attributes": {
                            "last_analysis_stats": {...},
                            "last_analysis_results": {...}
                        }
                    }
                }
            ]
    """
    try:
        with open(html_filepath, 'r', encoding='utf-8') as f:
            html_content = f.read()
        
        vt_html = generate_virustotal_section(virustotal_results)
        
        if '<div id="virustotal-placeholder"></div>' in html_content:
            html_content = html_content.replace(
                '<div id="virustotal-placeholder"></div>',
                vt_html
            )
        else:
            marker = '<div class="section">\n            <h2>권고 조치 방안</h2>'
            if marker in html_content:
                html_content = html_content.replace(marker, f'{vt_html}\n        {marker}')
        
        with open(html_filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        stats = {
            "total": len(virustotal_results),
            "malicious": 0,
            "suspicious": 0,
            "clean": 0
        }
        
        for result in virustotal_results:
            try:
                analysis_stats = result['data']['attributes']['last_analysis_stats']
                if analysis_stats.get('malicious', 0) > 0:
                    stats['malicious'] += 1
                elif analysis_stats.get('suspicious', 0) > 0:
                    stats['suspicious'] += 1
                else:
                    stats['clean'] += 1
            except:
                pass
        
        return json.dumps({
            "status": "success",
            "message": "VirusTotal 섹션 추가 완료",
            "updated_file": html_filepath,
            "statistics": stats
        }, indent=2)
        
    except Exception as e:
        import traceback
        return json.dumps({
            "error": f"HTML 업데이트 중 오류: {str(e)}",
            "traceback": traceback.format_exc()
        }, indent=2)




def main():
    print("QRadar MCP Server - Optimized with VirusTotal Integration")

if __name__ == "__main__":
    mcp.run()