# qradar_mcp_server.py
import asyncio
import json
import sys
from mcp.server import Server
from mcp.types import Tool
from mcp.server.stdio import stdio_server

# 네 기존 파일 그대로 import
from test_qradar import APIClient, integrate_offense_data
from decoding_hex import HexDecoder

# 여기에 직접 입력
DEFAULT_SEC_TOKEN = "2cd1c231-78c8-4a4f-a972-6a3ab909d879"
DEFAULT_BASE_URL = "https://10.10.10.20:443"

server = Server("qradar-server")

@server.list_tools()
async def list_tools():
    return [
        Tool(
            name="get_qradar_security_report",
            description="QRadar에서 최신 보안 offense 데이터를 수집하여 보고서용 데이터 반환",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": []
            }
        )
    ]

@server.call_tool()
async def call_tool(name: str, arguments: dict):
    if name == "get_qradar_security_report":
        try:
            # 하드코딩된 값 사용
            sec_token = DEFAULT_SEC_TOKEN
            base_url = DEFAULT_BASE_URL
            
            # 네 기존 코드 그대로 실행
            client = APIClient(base_url, sec_token)
            decoder = HexDecoder()
            
            print("QRadar 통합 데이터 수집 시작...", file=sys.stderr)
            integrated_data = integrate_offense_data(client, decoder)
            
            result = {
                "success": True,
                "data": integrated_data,
                "total_offenses": len(integrated_data),
                "total_events": sum(len(offense.get('events', [])) for offense in integrated_data)
            }
            
            return {"content": [{"type": "text", "text": json.dumps(result, ensure_ascii=False, indent=2)}]}
            
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            error_result = {"success": False, "error": str(e), "data": []}
            return {"content": [{"type": "text", "text": json.dumps(error_result)}]}

async def main():
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options()
        )

if __name__ == "__main__":
    asyncio.run(main())