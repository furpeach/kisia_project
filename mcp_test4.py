import sys
import warnings
import os
import logging
import json

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
        # 타임아웃 10분으로 증가
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
    """
    Source IP 병렬 조회 (최적화)
    순차: N개 × 0.5초 = N/2초
    병렬: 0.5초 (N배 빠름)
    """
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
    
    # 모든 IP를 동시에 조회
    tasks = [fetch_ip(addr_id) for addr_id in address_ids]
    results = await asyncio.gather(*tasks)
    
    # None 제거
    return [ip for ip in results if ip is not None]

async def get_destination_ips(client, address_ids):
    """
    Destination IP 병렬 조회 (최적화)
    """
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
            
            # Rule names 조회
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
            
            # Source/Destination IPs 병렬 조회
            source_address_ids = offense_detail.get('source_address_ids', [])
            source_ips = await get_source_ips(client, source_address_ids)
            print(f"INFO: offense_id {offense_id} - Source IPs: {len(source_ips)}개")
            
            local_destination_address_ids = offense_detail.get('local_destination_address_ids', [])
            destination_ips = await get_destination_ips(client, local_destination_address_ids)
            print(f"INFO: offense_id {offense_id} - Destination IPs: {len(destination_ips)}개")
            
            # Events 정보 조회
            events_data = await get_events_with_payload(client, start_time, last_updated_time, decoder)
            
            # 통합
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
            
            # Rule 이름 조회
            rules_detail = []
            for rule in offense_detail.get('rules', []):
                rule_name = await get_rule_name(client, rule['id'])
                rules_detail.append({
                    'id': rule['id'],
                    'type': rule['type'],
                    'name': rule_name
                })
            
            # IP 병렬 조회
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
    """
    QRadar에서 전체 offense 데이터를 수집하여 파일로 저장
    
    타임아웃: 10분
    최적화: IP 병렬 조회
    """
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
    """
    지정한 기간의 QRadar offense 데이터 수집
    
    타임아웃: 10분
    최적화: IP 병렬 조회
    """
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
async def qradar_generate_report(
    filepath: str,
    output_format: str = "markdown",
    max_event_samples: int = 3
) -> str:
    """저장된 파일에서 분석 보고서 생성"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        all_offenses = data.get('data', [])
        collected_at = data.get('collected_at', 'N/A')
        
        if output_format == "markdown":
            report_lines = [
                "# QRadar Offense 분석 보고서",
                f"\n**데이터 수집 시간**: {collected_at}",
                f"**전체 Offense 수**: {len(all_offenses)}",
                f"**LogSource ID**: 163",
                "\n---\n"
            ]
            
            total_events = sum(
                len(o.get('events', [])) 
                for o in all_offenses 
                if isinstance(o.get('events'), list)
            )
            
            severity_counts = {}
            for o in all_offenses:
                sev = o.get('severity', 'Unknown')
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
            
            report_lines.append("## 전체 통계")
            report_lines.append(f"\n- **총 Offense 수**: {len(all_offenses)}")
            report_lines.append(f"- **총 이벤트 수**: {total_events}")
            report_lines.append("\n**심각도별 분포**:")
            
            for sev, count in sorted(severity_counts.items(), reverse=True):
                report_lines.append(f"- Severity {sev}: {count}개")
            
            report_lines.append("\n---\n")
            
            for idx, offense in enumerate(all_offenses, 1):
                report_lines.append(f"\n## {idx}. Offense ID: {offense.get('id')}")
                
                report_lines.append(f"\n**설명**: {offense.get('description', 'N/A')}")
                report_lines.append(
                    f"\n**심각도**: {offense.get('severity')} | "
                    f"**크기**: {offense.get('magnitude')} | "
                    f"**상태**: {offense.get('status', 'N/A')}"
                )
                report_lines.append(f"**이벤트 수**: {offense.get('event_count', 0)}")
                
                source_ips = offense.get('source_ips', [])
                if source_ips:
                    report_lines.append(f"\n**출발지 IP**: {', '.join(source_ips)}")
                
                dest_ips = offense.get('destination_ips', [])
                if dest_ips:
                    report_lines.append(f"**목적지 IP**: {', '.join(dest_ips)}")
                
                rules = offense.get('rules', [])
                if rules:
                    report_lines.append("\n**탐지 규칙**:")
                    for rule in rules:
                        report_lines.append(
                            f"- {rule.get('name', 'Unknown')} "
                            f"(ID: {rule.get('id')}, Type: {rule.get('type', 'N/A')})"
                        )
                
                events = offense.get('events', [])
                if isinstance(events, list) and events:
                    sample_count = min(len(events), max_event_samples)
                    
                    report_lines.append(
                        f"\n**이벤트 샘플** "
                        f"(총 {len(events)}개 중 {sample_count}개):"
                    )
                    
                    for event in events[:sample_count]:
                        report_lines.append(
                            f"```json\n"
                            f"{json.dumps(event, indent=2, ensure_ascii=False)}\n"
                            f"```"
                        )
                
                report_lines.append("\n---")
            
            report_content = "\n".join(report_lines)
            report_filename = filepath.replace('.json', '_report.md')
            
            with open(report_filename, 'w', encoding='utf-8') as f:
                f.write(report_content)
            
            return json.dumps({
                "status": "success",
                "message": "마크다운 보고서 생성 완료",
                "report_filepath": report_filename,
                "total_offenses": len(all_offenses),
                "preview": report_content[:3000] + "\n\n... (이하 생략)"
            }, indent=2)
        
        return json.dumps({"error": "지원하지 않는 출력 형식"}, indent=2)
        
    except Exception as e:
        import traceback
        return json.dumps({
            "error": f"보고서 생성 중 오류: {str(e)}",
            "traceback": traceback.format_exc()
        }, indent=2)

def main():
    print("QRadar MCP Server - Optimized (Timeout 10min + Parallel IP)")

if __name__ == "__main__":
    mcp.run()