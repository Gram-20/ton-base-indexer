import asyncio
import codecs
import hashlib
from tvm_valuetypes.cell import deserialize_boc

from sqlalchemy.orm import joinedload, Session, contains_eager
from sqlalchemy.future import select
from sqlalchemy.dialects.postgresql import insert as insert_pg


from indexer.database import *
from loguru import logger

async def get_existing_seqnos_from_list(session, seqnos):
    seqno_filters = [Block.seqno == seqno for seqno in seqnos]
    seqno_filters = or_(*seqno_filters)
    existing_seqnos = await session.execute(select(Block.seqno).\
                              filter(Block.workchain == MASTERCHAIN_INDEX).\
                              filter(Block.shard == MASTERCHAIN_SHARD).\
                              filter(seqno_filters))
    existing_seqnos = existing_seqnos.all()
    return [x[0] for x in existing_seqnos]

async def get_existing_seqnos_between_interval(session, min_seqno, max_seqno):
    """
    Returns set of tuples of existing seqnos: {(19891542,), (19891541,), (19891540,)}
    """
    seqnos_already_in_db = await session.execute(select(Block.seqno).\
                                   filter(Block.workchain==MASTERCHAIN_INDEX).\
                                   filter(Block.shard == MASTERCHAIN_SHARD).\
                                   filter(Block.seqno >= min_seqno).\
                                   filter(Block.seqno <= max_seqno))
    seqnos_already_in_db = seqnos_already_in_db.all()
    return set(seqnos_already_in_db)

def chunks(lst, n):
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        yield lst[i:i + n]

async def insert_by_seqno_core(session, blocks_raw, headers_raw, transactions_raw, indexer):
    meta = Base.metadata
    block_t = meta.tables[Block.__tablename__]
    block_headers_t = meta.tables[BlockHeader.__tablename__]
    transaction_t = meta.tables[Transaction.__tablename__]
    message_t = meta.tables[Message.__tablename__]
    code_t = meta.tables[Code.__tablename__]
    accounts_t = meta.tables[Accounts.__tablename__]

    async with engine.begin() as conn:
        mc_block_id = None
        shard_headers = []
        in_msgs_by_hash = {}

        # Map of "active" accounts to tx_id, i.e. accounts which are able to process transactions,
        # and hence have a state
        active_accounts = {}

        for block_raw, header_raw, txs_raw in zip(blocks_raw, headers_raw, transactions_raw):
            s_block = Block.raw_block_to_dict(block_raw)
            s_block['masterchain_block_id'] = mc_block_id

            res = await conn.execute(block_t.insert(), [s_block])
            block_id = res.inserted_primary_key[0]
            if mc_block_id is None:
                mc_block_id = block_id

            s_header = BlockHeader.raw_header_to_dict(header_raw)
            s_header['block_id'] = block_id
            shard_headers.append(s_header)

            for tx_raw, tx_details_raw in txs_raw:
                tx = Transaction.raw_transaction_to_dict(tx_raw, tx_details_raw)
                if tx is None:
                    continue
                tx['block_id'] = block_id
                res = await conn.execute(transaction_t.insert(), [tx])

                if 'in_msg' in tx_details_raw:
                    in_msg_raw = tx_details_raw['in_msg']
                    in_msg = Message.raw_msg_to_dict(in_msg_raw)
                    in_msg['in_tx_id'] = res.inserted_primary_key[0]
                    in_msgs_by_hash[in_msg['hash']] = in_msg

                    # check accounts only for incoming transactions
                    if tx['compute_exit_code'] is not None:
                        acc = in_msg['destination']
                        if acc not in active_accounts:
                            active_accounts[acc] = res.inserted_primary_key[0]


        await conn.execute(block_headers_t.insert(), shard_headers)

        msgs_to_insert = list(filter(lambda x: x['comment'] is not None and len(x['comment']) > 0, in_msgs_by_hash.values()))

        if len(msgs_to_insert):
            msg_ids = []
            for chunk in chunks(msgs_to_insert, 1000):
                msg_ids += (await conn.execute(message_t.insert().returning(message_t.c.msg_id).values(chunk))).all()


        accounts_to_check = {}
        for address, tx_id in active_accounts.items():
            if not await is_account_known(conn, address):
                accounts_to_check[address] = tx_id
        logger.info(f"Accounts to check: {len(accounts_to_check)}")

        checked_states = await asyncio.gather(*[indexer.get_account_info_for_block(blocks_raw[0], address) for address in accounts_to_check.keys()])
        if len(checked_states) != len(accounts_to_check):
            logger.warning(f"Something missing - got {len(checked_states)} accounts states from {len(accounts_to_check)}")
        codes_to_insert = []
        accounts_to_insert = []
        for state in checked_states:
            if state.get('code', None) is None or len(state['code']) == 0:
                logger.warning(f"State with empty code: {state}")
                continue
            code_hash = cell_hash(state['code'], state['address'])
            state['code_hash'] = code_hash

            if code_hash:
                codes_to_insert.append({'hash': code_hash, 'code': state['code']})
            accounts_to_insert.append({
                'address': state['address'],
                'first_tx': accounts_to_check[state['address']],
                'code_hash': code_hash,
                'data': state['data']
            })

        if len(checked_states) > 0:
            if len(codes_to_insert) > 0:
                await conn.execute(insert_pg(code_t).values(codes_to_insert).on_conflict_do_nothing())
            if len(accounts_to_insert) > 0:
                await conn.execute(insert_pg(accounts_t).values(accounts_to_insert).on_conflict_do_nothing())
            logger.info(f"Updated {len(checked_states)} accounts")

def cell_b64(cell):
    return codecs.encode(cell.hash(), "base64").decode().strip()

def cell_hash(boc, address):
    try:
        if len(boc) > 0:
            code_cell_boc = codecs.decode(codecs.encode(boc, 'utf8'), 'base64')
            return cell_b64(deserialize_boc(code_cell_boc))
    except NotImplementedError:
        logger.error(f"NotImplementedError for {address}")
        return codecs.decode(codecs.encode(hashlib.sha256(codecs.encode(boc, 'utf8')).digest(), "base64"), 'utf-8').strip()
    except RecursionError:
        logger.error(f"RecursionError for {address}")
        return codecs.decode(codecs.encode(hashlib.sha256(codecs.encode(boc, 'utf8')).digest(), "base64"), 'utf-8').strip()

async def is_account_known(session: Session, address: str):
    query = await session.execute(select(Accounts.address) \
                                  .filter(Accounts.address == address) \
                                  .limit(1))

    return query.first() is not None