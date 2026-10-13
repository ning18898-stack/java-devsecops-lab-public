"""Fixed loopback binding; don't add external hosts or trust proxy headers."""
import argparse
import uvicorn
from app.main import create_app


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    uvicorn.run(create_app(), host="127.0.0.1", port=args.port, proxy_headers=False, access_log=False)
