"""run the server:  python -m server [--data-dir data] [--port 5000]"""
import argparse

from server.app import create_app

parser = argparse.ArgumentParser(prog="python -m server")
parser.add_argument("--data-dir", default="data")
parser.add_argument("--port", type=int, default=5000)
args = parser.parse_args()

# localhost only for the demo. a real deployment would sit behind https
create_app(args.data_dir).run(host="127.0.0.1", port=args.port, threaded=True)
