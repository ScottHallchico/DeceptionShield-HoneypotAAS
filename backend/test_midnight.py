import asyncio
from app.services.midnight.threat_ledger import attest_indicator, query_indicator

async def main():
    print("Attesting...")
    res1 = await attest_indicator("1.2.3.4", "critical", "T1001")
    print(res1)
    
    print("Querying...")
    res2 = await query_indicator("1.2.3.4")
    print(res2)

if __name__ == "__main__":
    asyncio.run(main())
