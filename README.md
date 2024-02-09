# TON Base indexer

The Simple TON Blockchain indexer is designed to index all messages with comments. 
It serves as a starting point for the Gram-20 indexer architecture, 
offering a scalable and resilient data source for protocol implementation.

## Architecture

This tool is based on [re-doubt/ton-indexer](https://github.com/re-doubt/ton-indexer), which itself
is based on [toncenter/ton-indexer](https://github.com/toncenter/ton-indexer).
The indexer architecture is shown on the following image:
![indexer](./Indexer%20arch.png)

## Deployment

Prerequisites: docker, docker-compose.

1. Prepare network config: download it from [api.tontech.io](https://api.tontech.io/ton/wallet-mainnet.autoconf.json). 
If you are going to use your own private node, update ``liteservers`` section. _Note: only first liteserver
will be used for indexing!_
2. Prepare config in .env:
``sh
TON_INDEXER_START_SEQNO=34880000  
TON_INDEXER_LITE_SERVER_CONFIG=./wallet-mainnet.autoconf.json
``
If you are intended to index Gram-20 data from the protocol start, use __34880000__ as a value for ``TON_INDEXER_START_SEQNO_``
If you are using dumps from [gramscan.org](https://gramscan.org/dumps), get value from state.json, 
and use **seqno - 100** in  ``TON_INDEXER_START_SEQNO_``. 
3. Build docker images:
``sh
docker compose build
``
4. Create postgres password (using openssl rand, or any other tool, but pay attention to avoid \n):
``sh
openssl rand -base64 10  | tr -d "\n" > private/postgres_password
``
5. Run containers:
``sh
docker compose up -d
``
6. Check DB for new messages

### Production deployment considerations

1. Use your own private node. To configure node, use [official documentation](https://docs.ton.org/participate/run-nodes/full-node),
or build docker image from the [TON monorepo](https://github.com/ton-blockchain/ton). To bootstrap node
using [dumps](https://dump.ton.org/) is highly recommended.
2. Use replicated postgres database configuration, to avoid availability. Read clients should
use read replicas to avoid load spikes from the indexer.
3. Default docker-compose provides open port for postgres, which is unsecure.

