import json
import pprint
from tqdm import tqdm
import time

# 바이너리 데이터 언패킹 (네트)
import struct
import re

class HexDecoder:
    def __init__(self):
        pass
        
    def hex2utf(self, packet_hex):
        try:
            # 16진수 문자열 -> 바이트 배열
            packet_bytes = bytes.fromhex(packet_hex)
            
            # 기본값
            src_ip = dst_ip = "unknown"
            src_port = dst_port = 0
            protocol = "unknown"
            
            # IP 정보 추출 (Ethernet 14바이트 + IP 헤더)
            if len(packet_bytes) >= 34:
                ip_header = packet_bytes[14:34]
                src_ip = '.'.join([str(b) for b in ip_header[12:16]])
                dst_ip = '.'.join([str(b) for b in ip_header[16:20]])
                proto_num = ip_header[9]
                protocol = "TCP" if proto_num == 6 else "UDP" if proto_num == 17 else f"PROTO{proto_num}"
            
            # TCP 포트 정보 추출
            if len(packet_bytes) >= 54:
                tcp_header = packet_bytes[34:54]
                src_port = struct.unpack('!H', tcp_header[0:2])[0]
                dst_port = struct.unpack('!H', tcp_header[2:4])[0]
            
            # HTTP 페이로드 추출
            payload = packet_bytes[54:]
            http_data = payload.decode('utf-8', errors='ignore').replace('\r', ' ').replace('\n', ' ')
            http_data = ' '.join(http_data.split())  # 연속 공백 제거
            
            # syslog 형식으로 조합
            syslog_entry = f"{protocol} {src_ip}:{src_port}->{dst_ip}:{dst_port} {http_data}"
            
            return syslog_entry
            
        except Exception as e:
            return f"Parse error: {e}"
        
    def export_packet(self, export_data, output_file="final_decoded_hex.json"):
        hex_results = []
        
        for item in tqdm(export_data):
            for event in item['events']:
                payload = event['utf8_payload']
                
                # packet_hex
                if 'packet_hex=' in payload:
                    hex_match = re.search(r'packet_hex=([^\s]+)', payload)
                    if hex_match and hex_match.group(1):
                        packet_hex = hex_match.group(1)
                        # log_id 
                        log_match = re.search(r'log_id=([^\s]+)', payload)
                        if log_match:
                            log_id = log_match.group(1) 
                            try: 
                                # syslog 형식 파싱
                                syslog_format = self.hex2utf(packet_hex)
                            except:
                                syslog_format = "파싱 실패"
                                
                            result = {
                                'qid' : event['QID'], 
                                'log_id': log_id,
                                # 'packet_hex': packet_hex,
                                'decoded_text': syslog_format          
                            }
                            hex_results.append(result)
        
        # 파일로 저장
        with open(output_file, "w", encoding='utf-8') as f:
            json.dump(hex_results, f, ensure_ascii=False, indent=4)
        
        return hex_results    


    
