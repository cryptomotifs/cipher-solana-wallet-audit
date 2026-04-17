"""Clean source file. Uses env vars, no hardcoded secrets."""

import os

RPC_URL = os.environ["SOLANA_RPC_URL"]
SECRET_KEY = os.environ["WALLET_SECRET_KEY"]


def main() -> None:
    print(f"Connecting to {RPC_URL!r}...")


if __name__ == "__main__":
    main()
