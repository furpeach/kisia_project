import json
import pprint
import time
import struct
import re

class HexDecoder:
    def __init__(self):
        pass
    
    def is_valid_hex(self, hex_string):
        """유효한 hex 문자열인지 검증"""
        if not hex_string or len(hex_string) % 2 != 0:
            return False
        hex_clean = hex_string.strip()
        return bool(re.match(r'^[0-9a-fA-F]+$', hex_clean))
        
    def hex2utf(self, packet_hex):
        """HEX를 읽을 수 있는 텍스트로 디코딩"""
        try:
            if not self.is_valid_hex(packet_hex):
                return None
            
            packet_bytes = bytes.fromhex(packet_hex)
            
            if len(packet_bytes) < 34:
                return None
            
            # IP 정보 추출
            ip_header = packet_bytes[14:34]
            src_ip = '.'.join([str(b) for b in ip_header[12:16]])
            dst_ip = '.'.join([str(b) for b in ip_header[16:20]])
            proto_num = ip_header[9]
            protocol = "TCP" if proto_num == 6 else "UDP" if proto_num == 17 else f"PROTO{proto_num}"
            
            # 포트 정보 추출
            src_port = dst_port = 0
            if len(packet_bytes) >= 54:
                tcp_header = packet_bytes[34:54]
                src_port = struct.unpack('!H', tcp_header[0:2])[0]
                dst_port = struct.unpack('!H', tcp_header[2:4])[0]
            
            # 페이로드 추출
            payload = packet_bytes[54:]
            http_data = payload.decode('utf-8', errors='ignore').replace('\r', ' ').replace('\n', ' ')
            http_data = ' '.join(http_data.split())
            
            syslog_entry = f"{protocol} {src_ip}:{src_port} -> {dst_ip}:{dst_port} {http_data}"
            
            return syslog_entry
            
        except Exception as e:
            return None
        
    def export_packet(self, export_data, output_file="final_decoded_hex.json"):
        all_results = []
        
        for item in export_data:
            for event in item['events']:
                payload = event['utf8_payload']
                
                # packet_hex= 포함 여부 확인
                if 'packet_hex=' in payload:
                    # hex 값 추출
                    hex_match = re.search(r'packet_hex=([0-9a-fA-F]+)', payload)
                    if hex_match:
                        packet_hex = hex_match.group(1)
                        decoded = self.hex2utf(packet_hex)
                        
                        if decoded:
                            # hex 디코딩 성공 → 디코딩된 결과 저장
                            result = decoded
                        else:
                            # hex 디코딩 실패 → 원본 저장
                            result = payload
                    else:
                        # hex 값 추출 실패 → 원본 저장
                        result = payload
                else:
                    # packet_hex 없음 → UTF-8 텍스트 그대로 저장
                    result = payload
                
                all_results.append(result)
        
        # 파일로 저장
        with open(output_file, "w", encoding='utf-8') as f:
            json.dump(all_results, f, ensure_ascii=False, indent=4)
        
        return all_results