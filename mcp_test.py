from fastmcp import FastMCP
from datetime import datetime
from dotenv import load_dotenv
import json
import os
import httpx
import asyncio
from typing import List, Dict, Optional
from tqdm import tqdm

# decoding_hex 불러오기 (기존 모듈 사용)
from decoding_hex import HexDecoder

load_dotenv()

# 환경변수에서 QRadar 설정 로드
# URL_BASE = os.getenv("QRADAR_BASE_URL")
URL_BASE = "https://112.216.102.242:443"
SEC_TOKEN = "2cd1c231-78c8-4a4f-a972-6a3ab909d879"
# SEC_TOKEN = os.getenv("QRADAR_SEC_TOKEN")

mcp = FastMCP("QRadar MCP Server")

class AsyncQRadarClient:
    def __init__(self, base_url: str, sec_token: str):
        self.base_url = base_url
        self.headers = {
            'SEC': sec_token,
            'Content-Type': 'application/json',
            'accept': 'application/json'
        }
        self.endpoints = {
            'about': '/api/system/about',
            'offenses': '/api/siem/offenses',
            'offense_detail': '/api/siem/offenses/{}',
            'search': '/api/ariel/searches',
            'search_status': '/api/ariel/searches/{}',
            'search_results': '/api/ariel/searches/{}/results',
            'rules': '/api/analytics/rules/{}'
        }

    async def get(self, endpoint_name: str, offense_id: Optional[str] = None) -> dict:
        """비동기 GET 요청"""
        if offense_id:
            url = f"{self.base_url}{self.endpoints[endpoint_name].format(offense_id)}"
        else:
            url = f"{self.base_url}{self.endpoints[endpoint_name]}"
        
        async with httpx.AsyncClient(verify=False, timeout=30.0) as client:
            try:
                response = await client.get(url, headers=self.headers)
                # 응답 상태코드 확인
                response.raise_for_status()
                return response.json()
            except Exception as e:
                return {"error": str(e)}

    async def post(self, endpoint_name: str, param: str) -> dict:
        """비동기 POST 요청"""
        if endpoint_name == 'search':
            url = f"{self.base_url}{self.endpoints[endpoint_name]}?query_expression={param}"
        else:
            url = f"{self.base_url}{self.endpoints[endpoint_name].format(param)}"
        
        async with httpx.AsyncClient(verify=False, timeout=30.0) as client:
            try:
                response = await client.post(url, headers=self.headers)
                # 응답 상태코드 확인
                response.raise_for_status()
                return response.json()
            except Exception as e:
                return {"error": str(e)}

    def create_logsourceid_aql(self, start_time: int, last_updated_time: int) -> str:
        """AQL 쿼리 생성"""
        return f"SELECT UTF8(payload), QID FROM events WHERE logsourceid = 163 AND QID = 1002750255 START {start_time} STOP {last_updated_time}"

# 전역 클라이언트 인스턴스
client = AsyncQRadarClient(URL_BASE, SEC_TOKEN) if URL_BASE and SEC_TOKEN else None

@mcp.tool()
async def qradar_api_test() -> str:
    """QRadar API 연결 테스트"""
    if not client:
        return json.dumps({"error": "QRadar 클라이언트가 설정되지 않았습니다. 환경변수를 확인하세요."}, indent=2)
    
    response = await client.get('about')
    return json.dumps(response, indent=2)

@mcp.tool()
async def qradar_get_offenses() -> str:
    """QRadar offense 목록 조회"""
    if not client:
        return json.dumps({"error": "QRadar 클라이언트가 설정되지 않았습니다."}, indent=2)
    
    response = await client.get('offenses')
    return json.dumps(response, indent=2)

@mcp.tool()
async def qradar_get_offense_detail(offense_id: str) -> str:
    """특정 offense 상세 정보 조회"""
    if not client:
        return json.dumps({"error": "QRadar 클라이언트가 설정되지 않았습니다."}, indent=2)
    
    response = await client.post('offense_detail', offense_id)
    return json.dumps(response, indent=2)

@mcp.tool()
async def qradar_get_rule_name(rule_id: str) -> str:
    """룰 ID로 룰 이름 조회"""
    if not client:
        return json.dumps({"error": "QRadar 클라이언트가 설정되지 않았습니다."}, indent=2)
    
    response = await client.get('rules', rule_id)
    return json.dumps(response, indent=2)

@mcp.tool()
async def qradar_search_events(start_time: str, last_updated_time: str) -> str:
    """시간 범위로 이벤트 조회 및 payload 디코딩"""
    if not client:
        return json.dumps({"error": "QRadar 클라이언트가 설정되지 않았습니다."}, indent=2)
    
    try:
        # HexDecoder 초기화
        decoder = HexDecoder()
        
        # AQL 쿼리 생성
        aql_query = client.create_logsourceid_aql(int(start_time), int(last_updated_time))
        
        # 검색 요청
        search_response = await client.post('search', aql_query)
        if 'error' in search_response:
            return json.dumps(search_response, indent=2)
        
        cursor_id = search_response['cursor_id']
        
        # 검색 완료까지 대기
        while True:
            status_response = await client.get('search_status', cursor_id)
            if 'error' in status_response:
                return json.dumps(status_response, indent=2)
                
            if status_response['status'] == 'COMPLETED':
                break
            await asyncio.sleep(0.5)
        
        # 결과 조회
        search_id = status_response['search_id']
        results = await client.get('search_results', search_id)
        
        if 'error' in results:
            return json.dumps(results, indent=2)
        
        # payload 디코딩
        decoded_events = decoder.export_packet([results])
        
        return json.dumps({
            "raw_results": results,
            "decoded_events": decoded_events
        }, indent=2)
        
    except Exception as e:
        return json.dumps({"error": f"이벤트 검색 중 오류: {str(e)}"}, indent=2)

@mcp.tool()
async def qradar_get_filtered_offenses() -> str:
    """모든 offense 데이터 통합 (offense + rule names + events)"""
    if not client:
        return json.dumps({"error": "QRadar 클라이언트가 설정되지 않았습니다."}, indent=2)
    
    try:
        # HexDecoder 초기화
        decoder = HexDecoder()
        
        # offense 목록 조회
        offenses = await client.get('offenses')
        if 'error' in offenses:
            return json.dumps(offenses, indent=2)
        
        # logsource ID 163이 포함된 offense만 필터링
        offense_ids = []
        for offense_item in offenses:
            if any(log_source.get('id') == 163 for log_source in offense_item.get('log_sources', [])):
                offense_ids.append(offense_item['id'])
        
        integrated_data_list = []
        
        # 각 offense에 대해 통합 처리
        for offense_id in offense_ids:
            try:
                # 1. offense 상세 정보 조회
                offense_detail = await client.post('offense_detail', str(offense_id))
                if 'error' in offense_detail:
                    continue
                
                # 시간 검증
                start_time = offense_detail.get('start_time')
                last_updated_time = offense_detail.get('last_updated_time')
                
                if not start_time or not last_updated_time or start_time >= last_updated_time:
                    print(f"WARNING: offense_id {offense_id}: 잘못된 시간 범위 - 제외")
                    continue
                
                # 2. 룰 이름 매핑
                rules_detail = []
                for rule in offense_detail.get('rules', []):
                    rule_id = rule['id']
                    rule_info = await client.get('rules', str(rule_id))
                    
                    enhanced_rule = {
                        'id': rule['id'],
                        'type': rule['type'],
                        'name': rule_info.get('name', 'Unknown') if 'error' not in rule_info else 'Error'
                    }
                    rules_detail.append(enhanced_rule)
                
                # 3. 이벤트 조회 및 payload 디코딩 (완전한 처리)
                aql_query = client.create_logsourceid_aql(start_time, last_updated_time)
                search_response = await client.post('search', aql_query)
                
                if 'error' in search_response:
                    events_data = {"error": "검색 요청 실패"}
                else:
                    cursor_id = search_response['cursor_id']
                    
                    # 검색 완료까지 대기 (두 번째 코드와 동일한 로직)
                    while True:
                        status_response = await client.get('search_status', cursor_id)
                        if 'error' in status_response:
                            events_data = {"error": "상태 확인 실패"}
                            break
                            
                        if status_response['status'] == 'COMPLETED':
                            # 결과 조회
                            search_id = status_response['search_id']
                            results = await client.get('search_results', search_id)
                            
                            if 'error' in results:
                                events_data = {"error": "결과 조회 실패"}
                            else:
                                # payload 디코딩 (두 번째 코드와 동일)
                                events_data = decoder.export_packet([results])
                            break
                        
                        await asyncio.sleep(0.5)
                
                # 4. 통합 데이터 생성
                integrated_offense = offense_detail.copy()
                integrated_offense['rules'] = rules_detail
                integrated_offense['events'] = events_data
                
                integrated_data_list.append(integrated_offense)
                
            except Exception as e:
                print(f"offense_id {offense_id} 처리 중 오류: {str(e)}")
                continue

        # 결과 저장 (두 번째 코드와 동일)
        with open("integrated_offense_data.json", "w", encoding="utf-8") as f:
            json.dump(integrated_data_list, f, ensure_ascii=False, indent=4)
        
        return json.dumps({
            "processed_count": len(integrated_data_list),
            "total_filtered": len(offense_ids),
            "data": integrated_data_list
        }, indent=2, ensure_ascii=False)
        
    except Exception as e:
        return json.dumps({"error": f"데이터 통합 중 오류: {str(e)}"}, indent=2)

def main():
    print("Hello from QRadar MCP Server!")

if __name__ == "__main__":
    mcp.run()