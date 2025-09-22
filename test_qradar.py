# rest api를 사용하기 위한 모듈
import requests
import urllib3
import json
from typing import List, Dict, Optional

# 출력 detail
import pprint
from tqdm import tqdm
import time

# decoding_hex 불러오기
from decoding_hex import HexDecoder

from urllib3.exceptions import InsecureRequestWarning
urllib3.disable_warnings(InsecureRequestWarning)

class APIClient:
    def __init__(self, base_url, sec_token):
        self.base_url = base_url
        self.header = {
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

    def get(self, endpoint_name, offense_id=None):
        if offense_id:
            url = f"{self.base_url}{self.endpoints[endpoint_name].format(offense_id)}"
        else:
            url = f"{self.base_url}{self.endpoints[endpoint_name]}"
        
        r = requests.get(url, headers=self.header, verify=False)
        return r.json()

    def post(self, endpoint_name, param):
        if endpoint_name == 'search':
            url = f"{self.base_url}{self.endpoints[endpoint_name]}?query_expression={param}"
        else:
            url = f"{self.base_url}{self.endpoints[endpoint_name].format(param)}"
        
        resopnse = requests.post(url, headers=self.header, verify=False).json()
        return resopnse

    def create_logsourceid_aql(self, start_time, last_updated_time):
        return f"SELECT UTF8(payload), QID FROM events WHERE logsourceid = 163 AND QID = 1002750255 START {start_time} STOP {last_updated_time}"

def get_rule_name(client, rule_id):
    # rule id-name 매칭
    detail_rule_id = client.get('rules', rule_id)
    return detail_rule_id['name']

def get_events_with_payload(client, start_time, last_updated_time, decoder):
    # 시간 범위로 이벤트 조회 및 payload 디코딩
    # AQL 쿼리 생성
    aql_query = client.create_logsourceid_aql(start_time, last_updated_time)
    
    # 검색 요청
    search_response = client.post('search', aql_query)
    cursor_id = search_response['cursor_id']

    while True:
        status_response = client.get('search_status', cursor_id)
        if status_response['status'] == 'COMPLETED':
            break
        time.sleep(0.5)

    # 결과 조회
    search_id = status_response['search_id']
    results = client.get('search_results', search_id)
    
    # payload 디코딩
    decoded_events = decoder.export_packet([results])
    
    return decoded_events

def integrate_offense_data(client, decoder):
    # offense_id result + aql_query result + rule_name
    
    # offense 값 가져오기
    offenses = client.get('offenses')
    
    # logsource ID 163이 포함된 offense만 필터링
    offense_ids = []
    for offense_item in tqdm(offenses, desc="Offense 필터링"):
        if any(log_source['id'] == 163 for log_source in offense_item['log_sources']):
            offense_ids.append(offense_item['id'])

    # 데이터 통합하기 위한 리스트 
    integrated_data_list = []
    
    # 각 offense_id 값 post 조회
    for offense_id in tqdm(offense_ids, desc="Offense 통합 처리"):
        # 1. offense_id 값 post로 조회
        offense_detail = client.post('offense_detail', offense_id)
        
        # aql을 위한 시간 정보 저장
        start_time = offense_detail['start_time']
        last_updated_time = offense_detail['last_updated_time']
        
        # start_time과 last_update_time이 같을경우 오류가남. 오류 없애기
        if start_time >= last_updated_time:
            print(f"WARNING: offense_id {offense_id}: 잘못된 시간 범위 - 제외")
            continue
        
        # 2. rule_id - name mapping
        rules_detail = []
        # 각 rule 마다 반복
        for rule in offense_detail.get('rules', []):
            rule_id = rule['id']
            rule_name = get_rule_name(client, rule_id)
            
            enhanced_rule = {
                'id': rule['id'],
                'type': rule['type'],
                'name': rule_name
            }
            rules_detail.append(enhanced_rule)
        
        # 3. Events 정보 조회 및 payload 디코딩
        events_data = get_events_with_payload(client, start_time, last_updated_time, decoder)
        
        # 4. 모든 정보 통합
        integrated_offense = offense_detail.copy()  # 기존 모든 필드 유지
        integrated_offense['rules'] = rules_detail  # rules에 name 추가
        integrated_offense['events'] = events_data    # events 추가
        
        integrated_data_list.append(integrated_offense)

    return integrated_data_list

# 메인 실행 코드
if __name__ == "__main__":
    # 클라이언트 초기화
    SEC_TOKEN = '2cd1c231-78c8-4a4f-a972-6a3ab909d879'

    # client = APIClient('https://10.10.10.20:443', SEC_TOKEN)
    client = APIClient('https://112.216.102.242:443', SEC_TOKEN)
    
    # HexDecoder 초기화 (기존 코드에서 가져오기)
    decoder = HexDecoder()
    
    # 통합 데이터 수집
    integrated_data = integrate_offense_data(client, decoder)
        
    # 통합 결과 저장
    with open("integrated_offense_data.json", "w", encoding="utf-8") as f:
        json.dump(integrated_data, f, ensure_ascii=False, indent=4)
    
