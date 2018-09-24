// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "txdb.h"

#include "main.h"
#include "pow.h"
#include "stake.h"

#include <stdint.h>

#include <boost/thread.hpp>

static const char DB_COIN = 'C';
static const char DB_COINS = 'c';
static const char DB_BLOCK_FILES = 'f';
static const char DB_TXINDEX = 't';
static const char DB_BLOCK_INDEX = 'b';

////////////////////////////////////////// // imada
static const char DB_HEIGHTINDEX = 'h';
//////////////////////////////////////////

static const char DB_BEST_BLOCK = 'B';
static const char DB_HEAD_BLOCKS = 'H';
static const char DB_FLAG = 'F';
static const char DB_REINDEX_FLAG = 'R';
static const char DB_LAST_BLOCK = 'l';

extern map<uint256, uint256> mapProofOfStake;

using namespace std;

void static BatchWriteCoins(CLevelDBBatch& batch, const uint256& hash, const CCoins& coins)
{
    if (coins.IsPruned())
        batch.Erase(make_pair(DB_COINS, hash));
    else
        batch.Write(make_pair(DB_COINS, hash), coins);
}

void static BatchWriteHashBestChain(CLevelDBBatch& batch, const uint256& hash)
{
    batch.Write(DB_BEST_BLOCK, hash);
}

CCoinsViewDB::CCoinsViewDB(size_t nCacheSize, bool fMemory, bool fWipe) : db(GetDataDir() / "chainstate", nCacheSize, fMemory, fWipe)
{
}

bool CCoinsViewDB::GetCoins(const uint256& txid, CCoins& coins) const
{
    return db.Read(make_pair(DB_COINS, txid), coins);
}

bool CCoinsViewDB::HaveCoins(const uint256& txid) const
{
    return db.Exists(make_pair(DB_COINS, txid));
}

uint256 CCoinsViewDB::GetBestBlock() const
{
    uint256 hashBestChain;
    if (!db.Read(DB_BEST_BLOCK, hashBestChain))
        return uint256(0);
    return hashBestChain;
}

bool CCoinsViewDB::BatchWrite(CCoinsMap& mapCoins, const uint256& hashBlock)
{
    CLevelDBBatch batch;
    size_t count = 0;
    size_t changed = 0;
    for (CCoinsMap::iterator it = mapCoins.begin(); it != mapCoins.end();) {
        if (it->second.flags & CCoinsCacheEntry::DIRTY) {
            BatchWriteCoins(batch, it->first, it->second.coins);
            changed++;
        }
        count++;
        CCoinsMap::iterator itOld = it++;
        mapCoins.erase(itOld);
    }
    if (hashBlock != uint256(0))
        BatchWriteHashBestChain(batch, hashBlock);

    LogPrint("coindb", "Committing %u changed transactions (out of %u) to coin database...\n", (unsigned int)changed, (unsigned int)count);
    return db.WriteBatch(batch);
}

CBlockTreeDB::CBlockTreeDB(size_t nCacheSize, bool fMemory, bool fWipe) : CLevelDBWrapper(GetDataDir() / "blocks" / "index", nCacheSize, fMemory, fWipe)
{
}

bool CBlockTreeDB::WriteBlockIndex(const CDiskBlockIndex& blockindex)
{
    auto const &hash = blockindex.GetBlockHash();
    if (blockindex.IsProofOfStake()) {
        if (blockindex.hashProofOfStake == 0) {
            uint256 hashProofOfStake;
            if (stake->GetProof(hash, hashProofOfStake)) {
                CDiskBlockIndex blockindexFixed(&blockindex);
                blockindexFixed.hashProofOfStake = hashProofOfStake;
                return Write(make_pair(DB_BLOCK_INDEX, hash), blockindexFixed);
            } else {
#               if 0
                LogPrint("debug", "%s: zero stake block %s", __func__, hash.GetHex());
#               else
                return error("%s: zero stake (block %s)", __func__, hash.GetHex());
#               endif
            }
        }
#   if 0
    } else if (!CheckProofOfWork(hash, blockindex.nBits, Params().GetConsensus())) {
        LogPrint("debug", "%s: bad work block %d %d %s", __func__, blockindex.nBits, blockindex.nHeight, hash.GetHex()); //return error("%s: invalid proof of work: %d %d %s", __func__, blockindex.nBits, blockindex.nHeight, hash.GetHex());
#   endif
    }
    return Write(make_pair(DB_BLOCK_INDEX, hash), blockindex);
}

bool CBlockTreeDB::WriteBlockFileInfo(int nFile, const CBlockFileInfo& info)
{
    return Write(make_pair(DB_BLOCK_FILES, nFile), info);
}

bool CBlockTreeDB::ReadBlockFileInfo(int nFile, CBlockFileInfo& info)
{
    return Read(make_pair(DB_BLOCK_FILES, nFile), info);
}

bool CBlockTreeDB::WriteLastBlockFile(int nFile)
{
    return Write(DB_LAST_BLOCK, nFile);
}

bool CBlockTreeDB::WriteReindexing(bool fReindexing)
{
    if (fReindexing)
        return Write(DB_REINDEX_FLAG, '1');
    else
        return Erase(DB_REINDEX_FLAG);
}

bool CBlockTreeDB::ReadReindexing(bool& fReindexing)
{
    fReindexing = Exists(DB_REINDEX_FLAG);
    return true;
}

bool CBlockTreeDB::ReadLastBlockFile(int& nFile)
{
    return Read(DB_LAST_BLOCK, nFile);
}

bool CCoinsViewDB::GetStats(CCoinsStats& stats) const
{
    /* It seems that there are no "const iterators" for LevelDB.  Since we
       only need read operations on it, use a const-cast to get around
       that restriction.  */
    boost::scoped_ptr<leveldb::Iterator> pcursor(const_cast<CLevelDBWrapper*>(&db)->NewIterator());
    pcursor->SeekToFirst();

    CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
    stats.hashBlock = GetBestBlock();
    ss << stats.hashBlock;
    CAmount nTotalAmount = 0;
    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();
        try {
            leveldb::Slice slKey = pcursor->key();
            CDataStream ssKey(slKey.data(), slKey.data() + slKey.size(), SER_DISK, CLIENT_VERSION);
            char chType;
            ssKey >> chType;
            if (chType == DB_COINS) {
                leveldb::Slice slValue = pcursor->value();
                CDataStream ssValue(slValue.data(), slValue.data() + slValue.size(), SER_DISK, CLIENT_VERSION);
                CCoins coins;
                ssValue >> coins;
                uint256 txhash;
                ssKey >> txhash;
                ss << txhash;
                ss << VARINT(coins.nVersion);
                ss << (coins.fCoinBase ? DB_COINS : 'n');
                ss << VARINT(coins.nHeight);
                stats.nTransactions++;
                for (unsigned int i = 0; i < coins.vout.size(); i++) {
                    const CTxOut& out = coins.vout[i];
                    if (!out.IsNull()) {
                        stats.nTransactionOutputs++;
                        ss << VARINT(i + 1);
                        ss << out;
                        nTotalAmount += out.nValue;
                    }
                }
                stats.nSerializedSize += 32 + slValue.size();
                ss << VARINT(0);
            }
            pcursor->Next();
        } catch (std::exception& e) {
            return error("%s : Deserialize or I/O error - %s", __func__, e.what());
        }
    }
    stats.nHeight = mapBlockIndex.find(GetBestBlock())->second->nHeight;
    stats.hashSerialized = ss.GetHash();
    stats.nTotalAmount = nTotalAmount;
    return true;
}

bool CBlockTreeDB::ReadTxIndex(const uint256& txid, CDiskTxPos& pos)
{
    return Read(make_pair(DB_TXINDEX, txid), pos);
}

bool CBlockTreeDB::WriteTxIndex(const std::vector<std::pair<uint256, CDiskTxPos> >& vect)
{
    CLevelDBBatch batch;
    for (std::vector<std::pair<uint256, CDiskTxPos> >::const_iterator it = vect.begin(); it != vect.end(); it++)
        batch.Write(make_pair(DB_TXINDEX, it->first), it->second);
    return WriteBatch(batch);
}

bool CBlockTreeDB::WriteFlag(const std::string& name, bool fValue)
{
    return Write(std::make_pair(DB_FLAG, name), fValue ? '1' : '0');
}

bool CBlockTreeDB::ReadFlag(const std::string& name, bool& fValue)
{
    char ch;
    if (!Read(std::make_pair(DB_FLAG, name), ch))
        return false;
    fValue = ch == '1';
    return true;
}

bool CBlockTreeDB::LoadBlockIndexGuts()
{
    boost::scoped_ptr<leveldb::Iterator> pcursor(NewIterator());

    CDataStream ssKeySet(SER_DISK, CLIENT_VERSION);
    ssKeySet << make_pair(DB_BLOCK_INDEX, uint256(0));
    pcursor->Seek(ssKeySet.str());

    CBlockIndex* pindexPrev = nullptr;

    int nDiscarded = 0;
    int nFirstDiscarded = INT_MAX;
    CLevelDBBatch batch;

    // Load mapBlockIndex
    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();
        try {
            leveldb::Slice slKey = pcursor->key();
            CDataStream ssKey(slKey.data(), slKey.data() + slKey.size(), SER_DISK, CLIENT_VERSION);
            char chType;
            ssKey >> chType;
            if (chType == DB_BLOCK_INDEX) {
                leveldb::Slice slValue = pcursor->value();
                CDataStream ssValue(slValue.data(), slValue.data() + slValue.size(), SER_DISK, CLIENT_VERSION);
                CDiskBlockIndex diskindex;
                ssValue >> diskindex;

                // Construct block index object
                CBlockIndex* pindexNew = InsertBlockIndex(diskindex.GetBlockHash());
                pindexNew->pprev = InsertBlockIndex(diskindex.hashPrev);
                pindexNew->pnext = InsertBlockIndex(diskindex.hashNext);
                pindexNew->nHeight = diskindex.nHeight;
                pindexNew->nFile = diskindex.nFile;
                pindexNew->nDataPos = diskindex.nDataPos;
                pindexNew->nUndoPos = diskindex.nUndoPos;
                pindexNew->nVersion = diskindex.nVersion;
                pindexNew->hashMerkleRoot = diskindex.hashMerkleRoot;
                pindexNew->nTime = diskindex.nTime;
                pindexNew->nBits = diskindex.nBits;
                pindexNew->nNonce = diskindex.nNonce;
                pindexNew->nStatus = diskindex.nStatus;
                pindexNew->nTx = diskindex.nTx;
                pindexNew->hashStateRoot  = diskindex.hashStateRoot; // imada
                pindexNew->hashUTXORoot   = diskindex.hashUTXORoot; // imada

                // Proof Of Stake
                pindexNew->nMint = diskindex.nMint;
                pindexNew->nMoneySupply = diskindex.nMoneySupply;
                pindexNew->nFlags = diskindex.nFlags;
                pindexNew->nStakeModifier = diskindex.nStakeModifier;
                pindexNew->prevoutStake = diskindex.prevoutStake;
                pindexNew->nStakeTime = diskindex.nStakeTime;
                pindexNew->hashProofOfStake = diskindex.hashProofOfStake;

                bool isPoW = (diskindex.nNonce != 0) && pindexNew->nHeight <= Params().LAST_POW_BLOCK();
                if (isPoW) {
                    auto const &hash(pindexNew->GetBlockHash());
                    if (!CheckProofOfWork(hash, pindexNew->nBits, Params().GetConsensus())) {
                        unsigned int nBits = pindexPrev ? pindexPrev->nBits : 0;
                        return error("%s: CheckProofOfWork failed: %d %s (%d, %d)", __func__, pindexNew->nHeight, hash.GetHex(), pindexNew->nBits, nBits);
                    }
                } else {
                    stake->MarkStake(pindexNew->prevoutStake, pindexNew->nStakeTime);
                    auto const &hash(pindexNew->GetBlockHash());
                    uint256 proof;
                    if (pindexNew->hashProofOfStake == 0) {
                        LogPrint("debug", "skip invalid indexed orphan block %d %s with empty data\n", pindexNew->nHeight, hash.GetHex());
                        nDiscarded++;
                        nFirstDiscarded = diskindex.nHeight < nFirstDiscarded ? diskindex.nHeight : nFirstDiscarded;
                        batch.Erase(make_pair(DB_BLOCK_INDEX, hash));
                        pcursor->Next();
                        continue;
                    } else if (stake->GetProof(hash, proof)) {
                        if (proof != pindexNew->hashProofOfStake)
                            return error("%s: diverged stake %s, %s (block %s)\n", __func__, 
                                         pindexNew->hashProofOfStake.GetHex(), proof.GetHex(), hash.GetHex());
                    } else {
                        stake->SetProof(hash, pindexNew->hashProofOfStake);
                    }
                }

                pindexPrev = pindexNew;
                pcursor->Next();
            } else {
                break; // if shutdown requested or finished loading block index
            }
        } catch (std::exception& e) {
            return error("%s : Deserialize or I/O error - %s", __func__, e.what());
        }
    }

    if (nDiscarded) {
        if (WriteBatch(batch)) {
            LogPrintf("pruned %d orphaned blocks from disk index\n", nDiscarded);
        } else {
            return error("%d invalid blocks in disk index, restart with -reindex is required! (first was %d)\n", nDiscarded, nFirstDiscarded);
        }
    }

    return true;
}

/////////////////////////////////////////////////////// // imada
bool CBlockTreeDB::WriteHeightIndex(const CHeightTxIndexKey &heightIndex, const std::vector<uint256>& hash) {
    CLevelDBBatch batch;
    batch.Write(std::make_pair(DB_HEIGHTINDEX, heightIndex), hash);
    return WriteBatch(batch);
}

int CBlockTreeDB::ReadHeightIndex(int low, int high, int minconf,
                                  std::vector<std::vector<uint256>> &blocksOfHashes,
                                  std::set<dev::h160> const &addresses) {

    if ((high < low && high > -1) || (high == 0 && low == 0) || (high < -1 || low < 0)) {
        return -1;
    }

    boost::scoped_ptr<leveldb::Iterator> pcursor(NewIterator());

    CDataStream ssKeySet(SER_DISK, CLIENT_VERSION);
    ssKeySet << std::make_pair(DB_HEIGHTINDEX, CHeightTxIndexIteratorKey(low));
    pcursor->Seek(ssKeySet.str());

    int curheight = 0;

    for (size_t count = 0; pcursor->Valid(); pcursor->Next()) {
        leveldb::Slice slKey = pcursor->key();
        CDataStream ssKey(slKey.data(), slKey.data() + slKey.size(), SER_DISK, CLIENT_VERSION);
        char chType;
        ssKey >> chType;
        if (chType == DB_HEIGHTINDEX) {
            CHeightTxIndexKey heightTxIndex;
            ssKey >> heightTxIndex;

            int nextHeight = heightTxIndex.height;

            if (high > -1 && nextHeight > high) {
                break;
            }

            if (minconf > 0) {
                int conf = chainActive.Height() - nextHeight;
                if (conf < minconf) {
                    break;
                }
            }

            curheight = nextHeight;

            auto address = heightTxIndex.address;
            if (!addresses.empty() && addresses.find(address) == addresses.end()) {
                continue;
            }

            leveldb::Slice slValue = pcursor->value();
            CDataStream ssValue(slValue.data(), slValue.data() + slValue.size(), SER_DISK, CLIENT_VERSION);
            std::vector<uint256> hashesTx;
            ssValue >> hashesTx;

            count += hashesTx.size();

            blocksOfHashes.push_back(hashesTx);

        } else {
            break;
        }

    }

    return curheight;
}

bool CBlockTreeDB::EraseHeightIndex(const unsigned int &height) {

    boost::scoped_ptr<leveldb::Iterator> pcursor(NewIterator());
    CLevelDBBatch batch;

    CDataStream ssKeySet(SER_DISK, CLIENT_VERSION);
    ssKeySet << std::make_pair(DB_HEIGHTINDEX, CHeightTxIndexIteratorKey(height));
    pcursor->Seek(ssKeySet.str());

    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();
        leveldb::Slice slKey = pcursor->key();
        CDataStream ssKey(slKey.data(), slKey.data() + slKey.size(), SER_DISK, CLIENT_VERSION);
        char chType;
        ssKey >> chType;
        if (chType == DB_HEIGHTINDEX) {
            CHeightTxIndexKey heightTxIndex;
            ssKey >> heightTxIndex;
            if (heightTxIndex.height == height) {
                batch.Erase(std::make_pair(DB_HEIGHTINDEX, heightTxIndex));
                pcursor->Next();
            }
        } else {
            break;
        }
    }

    return WriteBatch(batch);
}

bool CBlockTreeDB::WipeHeightIndex() {

    boost::scoped_ptr<leveldb::Iterator> pcursor(NewIterator());
    CLevelDBBatch batch;

    pcursor->SeekToFirst();

    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();
        leveldb::Slice slKey = pcursor->key();
        CDataStream ssKey(slKey.data(), slKey.data() + slKey.size(), SER_DISK, CLIENT_VERSION);
        char chType;
        ssKey >> chType;
        if (chType == DB_HEIGHTINDEX) {
            CHeightTxIndexKey heightTxIndex;
            ssKey >> heightTxIndex;
            batch.Erase(std::make_pair(DB_HEIGHTINDEX, heightTxIndex));
            pcursor->Next();
        } else {
            break;
        }
    }

    return WriteBatch(batch);
}

///////////////////////////////////////////////////////

