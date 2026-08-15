# Build btc-rpc-explorer with QubitCoin patches.
# Pin a stable release tag; bump intentionally when upgrading.
ARG BTC_RPC_EXPLORER_VERSION=v3.5.1

FROM node:20 AS builder
ARG BTC_RPC_EXPLORER_VERSION
WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends git python3 \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 --branch "${BTC_RPC_EXPLORER_VERSION}" \
    https://github.com/janoside/btc-rpc-explorer.git /workspace

COPY overlay/ /overlay/
COPY apply-patches.sh /apply-patches.sh
RUN chmod +x /apply-patches.sh && /apply-patches.sh /workspace

WORKDIR /workspace
RUN npm ci --omit=dev

FROM node:20-alpine
WORKDIR /workspace
COPY --from=builder /workspace /workspace

ENV BTCEXP_HOST=0.0.0.0
ENV BTCEXP_PORT=3002
ENV BTCEXP_COIN=QBTC

EXPOSE 3002
CMD ["npm", "start"]
