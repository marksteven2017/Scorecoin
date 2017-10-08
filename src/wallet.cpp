// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "wallet.h"
#include "walletdb.h"
#include "crypter.h"
#include "ui_interface.h"
#include "base58.h"
#include "coincontrol.h"

#include "walletdb.h"
#include "crypter.h"
#include "key.h"
#include "spork.h"
#include "darksend.h"
//#include "keepass.h"
//#include "instantx.h"
#include "masternode.h"

#include <boost/algorithm/string/replace.hpp>
#include <boost/range/algorithm.hpp>
#include <boost/numeric/ublas/matrix.hpp>

using namespace std;


bool bSpendZeroConfChange = true;
int64_t gcd(int64_t n, int64_t m) { return m == 0 ? n : gcd(m, n % m); }


static uint64_t CoinWeightCost(const COutput &out)
{
	int64_t nTimeWeight = (int64_t)GetTime() - (int64_t)out.tx->nTime;
	CBigNum bnCoinDayWeight = CBigNum(out.tx->vout[out.i].nValue) * nTimeWeight / (24 * 60 * 60);
	return bnCoinDayWeight.getuint64();
}

//////////////////////////////////////////////////////////////////////////////
//
// mapWallet
//

struct CompareValueOnly
{
    bool operator()(const pair<int64, pair<const CWalletTx*, unsigned int> >& t1,
                    const pair<int64, pair<const CWalletTx*, unsigned int> >& t2) const
    {
        return t1.first < t2.first;
    }
};

CPubKey CWallet::GenerateNewKey()
{
    bool fCompressed = CanSupportFeature(FEATURE_COMPRPUBKEY); // default to compressed public keys if we want 0.6.0 wallets

    RandAddSeedPerfmon();
    CKey secret;
    secret.MakeNewKey(fCompressed);

    // Compressed public keys were introduced in version 0.6.0
    if (fCompressed)
        SetMinVersion(FEATURE_COMPRPUBKEY);

    CPubKey pubkey = secret.GetPubKey();
    if (!AddKeyPubKey(secret, pubkey))
        throw std::runtime_error("CWallet::GenerateNewKey() : AddKey failed");
    return pubkey;
}

bool CWallet::AddKeyPubKey(const CKey& secret, const CPubKey &pubkey)
{
    if (!CCryptoKeyStore::AddKeyPubKey(secret, pubkey))
        return false;
    if (!fFileBacked)
        return true;
    if (!IsCrypted()) {
        return CWalletDB(strWalletFile).WriteKey(pubkey, secret.GetPrivKey());
    }
    return true;
}

bool CWallet::AddCryptedKey(const CPubKey &vchPubKey, const vector<unsigned char> &vchCryptedSecret)
{
    if (!CCryptoKeyStore::AddCryptedKey(vchPubKey, vchCryptedSecret))
        return false;
    if (!fFileBacked)
        return true;
    {
        LOCK(cs_wallet);
        if (pwalletdbEncryption)
            return pwalletdbEncryption->WriteCryptedKey(vchPubKey, vchCryptedSecret);
        else
            return CWalletDB(strWalletFile).WriteCryptedKey(vchPubKey, vchCryptedSecret);
    }
    return false;
}

bool CWallet::LoadCryptedKey(const CPubKey &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret)
{
    return CCryptoKeyStore::AddCryptedKey(vchPubKey, vchCryptedSecret);
}

bool CWallet::AddCScript(const CScript& redeemScript)
{
    if (!CCryptoKeyStore::AddCScript(redeemScript))
        return false;
    if (!fFileBacked)
        return true;
    return CWalletDB(strWalletFile).WriteCScript(Hash160(redeemScript), redeemScript);
}

bool CWallet::Unlock(const SecureString& strWalletPassphrase)
{
    if (!IsLocked())
        return false;

    CCrypter crypter;
    CKeyingMaterial vMasterKey;

    {
        LOCK(cs_wallet);
        BOOST_FOREACH(const MasterKeyMap::value_type& pMasterKey, mapMasterKeys)
        {
            if(!crypter.SetKeyFromPassphrase(strWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod))
                return false;
            if (!crypter.Decrypt(pMasterKey.second.vchCryptedKey, vMasterKey))
                return false;
            if (CCryptoKeyStore::Unlock(vMasterKey))
                return true;
        }
    }
    return false;
}

bool CWallet::ChangeWalletPassphrase(const SecureString& strOldWalletPassphrase, const SecureString& strNewWalletPassphrase)
{
    bool fWasLocked = IsLocked();

    {
        LOCK(cs_wallet);
        Lock();

        CCrypter crypter;
        CKeyingMaterial vMasterKey;
        BOOST_FOREACH(MasterKeyMap::value_type& pMasterKey, mapMasterKeys)
        {
            if(!crypter.SetKeyFromPassphrase(strOldWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod))
                return false;
            if (!crypter.Decrypt(pMasterKey.second.vchCryptedKey, vMasterKey))
                return false;
            if (CCryptoKeyStore::Unlock(vMasterKey))
            {
                int64 nStartTime = GetTimeMillis();
                crypter.SetKeyFromPassphrase(strNewWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod);
                pMasterKey.second.nDeriveIterations = pMasterKey.second.nDeriveIterations * (100 / ((double)(GetTimeMillis() - nStartTime)));

                nStartTime = GetTimeMillis();
                crypter.SetKeyFromPassphrase(strNewWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod);
                pMasterKey.second.nDeriveIterations = (pMasterKey.second.nDeriveIterations + pMasterKey.second.nDeriveIterations * 100 / ((double)(GetTimeMillis() - nStartTime))) / 2;

                if (pMasterKey.second.nDeriveIterations < 25000)
                    pMasterKey.second.nDeriveIterations = 25000;

                printf("Wallet passphrase changed to an nDeriveIterations of %i\n", pMasterKey.second.nDeriveIterations);

                if (!crypter.SetKeyFromPassphrase(strNewWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod))
                    return false;
                if (!crypter.Encrypt(vMasterKey, pMasterKey.second.vchCryptedKey))
                    return false;
                CWalletDB(strWalletFile).WriteMasterKey(pMasterKey.first, pMasterKey.second);
                if (fWasLocked)
                    Lock();
                return true;
            }
        }
    }

    return false;
}

void CWallet::SetBestChain(const CBlockLocator& loc)
{
    CWalletDB walletdb(strWalletFile);
    walletdb.WriteBestBlock(loc);
}

// This class implements an addrIncoming entry that causes pre-0.4
// clients to crash on startup if reading a private-key-encrypted wallet.
class CCorruptAddress
{
public:
    IMPLEMENT_SERIALIZE
    (
        if (nType & SER_DISK)
            READWRITE(nVersion);
    )
};

bool CWallet::SetMinVersion(enum WalletFeature nVersion, CWalletDB* pwalletdbIn, bool fExplicit)
{
    if (nWalletVersion >= nVersion)
        return true;

    // when doing an explicit upgrade, if we pass the max version permitted, upgrade all the way
    if (fExplicit && nVersion > nWalletMaxVersion)
            nVersion = FEATURE_LATEST;

    nWalletVersion = nVersion;

    if (nVersion > nWalletMaxVersion)
        nWalletMaxVersion = nVersion;

    if (fFileBacked)
    {
        CWalletDB* pwalletdb = pwalletdbIn ? pwalletdbIn : new CWalletDB(strWalletFile);
        if (nWalletVersion >= 40000)
        {
            // Versions prior to 0.4.0 did not support the "minversion" record.
            // Use a CCorruptAddress to make them crash instead.
            CCorruptAddress corruptAddress;
            pwalletdb->WriteSetting("addrIncoming", corruptAddress);
        }
        if (nWalletVersion > 40000)
            pwalletdb->WriteMinVersion(nWalletVersion);
        if (!pwalletdbIn)
            delete pwalletdb;
    }

    return true;
}

bool CWallet::SetMaxVersion(int nVersion)
{
    // cannot downgrade below current version
    if (nWalletVersion > nVersion)
        return false;

    nWalletMaxVersion = nVersion;

    return true;
}

bool CWallet::EncryptWallet(const SecureString& strWalletPassphrase)
{
    if (IsCrypted())
        return false;

    CKeyingMaterial vMasterKey;
    RandAddSeedPerfmon();

    vMasterKey.resize(WALLET_CRYPTO_KEY_SIZE);
    RAND_bytes(&vMasterKey[0], WALLET_CRYPTO_KEY_SIZE);

    CMasterKey kMasterKey;

    RandAddSeedPerfmon();
    kMasterKey.vchSalt.resize(WALLET_CRYPTO_SALT_SIZE);
    RAND_bytes(&kMasterKey.vchSalt[0], WALLET_CRYPTO_SALT_SIZE);

    CCrypter crypter;
    int64 nStartTime = GetTimeMillis();
    crypter.SetKeyFromPassphrase(strWalletPassphrase, kMasterKey.vchSalt, 25000, kMasterKey.nDerivationMethod);
    kMasterKey.nDeriveIterations = 2500000 / ((double)(GetTimeMillis() - nStartTime));

    nStartTime = GetTimeMillis();
    crypter.SetKeyFromPassphrase(strWalletPassphrase, kMasterKey.vchSalt, kMasterKey.nDeriveIterations, kMasterKey.nDerivationMethod);
    kMasterKey.nDeriveIterations = (kMasterKey.nDeriveIterations + kMasterKey.nDeriveIterations * 100 / ((double)(GetTimeMillis() - nStartTime))) / 2;

    if (kMasterKey.nDeriveIterations < 25000)
        kMasterKey.nDeriveIterations = 25000;

    printf("Encrypting Wallet with an nDeriveIterations of %i\n", kMasterKey.nDeriveIterations);

    if (!crypter.SetKeyFromPassphrase(strWalletPassphrase, kMasterKey.vchSalt, kMasterKey.nDeriveIterations, kMasterKey.nDerivationMethod))
        return false;
    if (!crypter.Encrypt(vMasterKey, kMasterKey.vchCryptedKey))
        return false;

    {
        LOCK(cs_wallet);
        mapMasterKeys[++nMasterKeyMaxID] = kMasterKey;
        if (fFileBacked)
        {
            pwalletdbEncryption = new CWalletDB(strWalletFile);
            if (!pwalletdbEncryption->TxnBegin())
                return false;
            pwalletdbEncryption->WriteMasterKey(nMasterKeyMaxID, kMasterKey);
        }

        if (!EncryptKeys(vMasterKey))
        {
            if (fFileBacked)
                pwalletdbEncryption->TxnAbort();
            exit(1); //We now probably have half of our keys encrypted in memory, and half not...die and let the user reload their unencrypted wallet.
        }

        // Encryption was introduced in version 0.4.0
        SetMinVersion(FEATURE_WALLETCRYPT, pwalletdbEncryption, true);

        if (fFileBacked)
        {
            if (!pwalletdbEncryption->TxnCommit())
                exit(1); //We now have keys encrypted in memory, but no on disk...die to avoid confusion and let the user reload their unencrypted wallet.

            delete pwalletdbEncryption;
            pwalletdbEncryption = NULL;
        }

        Lock();
        Unlock(strWalletPassphrase);
        NewKeyPool();
        Lock();

        // Need to completely rewrite the wallet file; if we don't, bdb might keep
        // bits of the unencrypted private key in slack space in the database file.
        CDB::Rewrite(strWalletFile);

    }
    NotifyStatusChanged(this);

    return true;
}

int64 CWallet::IncOrderPosNext(CWalletDB *pwalletdb)
{
    int64 nRet = nOrderPosNext++;
    if (pwalletdb) {
        pwalletdb->WriteOrderPosNext(nOrderPosNext);
    } else {
        CWalletDB(strWalletFile).WriteOrderPosNext(nOrderPosNext);
    }
    return nRet;
}

CWallet::TxItems CWallet::OrderedTxItems(std::list<CAccountingEntry>& acentries, std::string strAccount)
{
    CWalletDB walletdb(strWalletFile);

    // First: get all CWalletTx and CAccountingEntry into a sorted-by-order multimap.
    TxItems txOrdered;

    // Note: maintaining indices in the database of (account,time) --> txid and (account, time) --> acentry
    // would make this much faster for applications that do this a lot.
    for (map<uint256, CWalletTx>::iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
    {
        CWalletTx* wtx = &((*it).second);
        txOrdered.insert(make_pair(wtx->nOrderPos, TxPair(wtx, (CAccountingEntry*)0)));
    }
    acentries.clear();
    walletdb.ListAccountCreditDebit(strAccount, acentries);
    BOOST_FOREACH(CAccountingEntry& entry, acentries)
    {
        txOrdered.insert(make_pair(entry.nOrderPos, TxPair((CWalletTx*)0, &entry)));
    }

    return txOrdered;
}

void CWallet::WalletUpdateSpent(const CTransaction &tx)
{
    // Anytime a signature is successfully verified, it's proof the outpoint is spent.
    // Update the wallet spent flag if it doesn't know due to wallet.dat being
    // restored from backup or the user making copies of wallet.dat.
    {
        LOCK(cs_wallet);
        BOOST_FOREACH(const CTxIn& txin, tx.vin)
        {
            map<uint256, CWalletTx>::iterator mi = mapWallet.find(txin.prevout.hash);
            if (mi != mapWallet.end())
            {
                CWalletTx& wtx = (*mi).second;
                if (txin.prevout.n >= wtx.vout.size())
                    printf("WalletUpdateSpent: bad wtx %s\n", wtx.GetHash().ToString().c_str());
                else if (!wtx.IsSpent(txin.prevout.n) && IsMine(wtx.vout[txin.prevout.n]))
                {
                    printf("WalletUpdateSpent found spent coin %sbc %s\n", FormatMoney(wtx.GetCredit()).c_str(), wtx.GetHash().ToString().c_str());
                    wtx.MarkSpent(txin.prevout.n);
                    wtx.WriteToDisk();
                    NotifyTransactionChanged(this, txin.prevout.hash, CT_UPDATED);
                }
            }
        }
    }
}

void CWallet::MarkDirty()
{
    {
        LOCK(cs_wallet);
        BOOST_FOREACH(PAIRTYPE(const uint256, CWalletTx)& item, mapWallet)
            item.second.MarkDirty();
    }
}

bool CWallet::AddToWallet(const CWalletTx& wtxIn)
{
    uint256 hash = wtxIn.GetHash();
    {
        LOCK(cs_wallet);
        // Inserts only if not already there, returns tx inserted or tx found
        pair<map<uint256, CWalletTx>::iterator, bool> ret = mapWallet.insert(make_pair(hash, wtxIn));
        CWalletTx& wtx = (*ret.first).second;
        wtx.BindWallet(this);
        bool fInsertedNew = ret.second;
        if (fInsertedNew)
        {
            wtx.nTimeReceived = GetAdjustedTime();
            wtx.nOrderPos = IncOrderPosNext();

            wtx.nTimeSmart = wtx.nTimeReceived;
            if (wtxIn.hashBlock != 0)
            {
                if (mapBlockIndex.count(wtxIn.hashBlock))
                {
                    unsigned int latestNow = wtx.nTimeReceived;
                    unsigned int latestEntry = 0;
                    {
                        // Tolerate times up to the last timestamp in the wallet not more than 5 minutes into the future
                        int64 latestTolerated = latestNow + 300;
                        std::list<CAccountingEntry> acentries;
                        TxItems txOrdered = OrderedTxItems(acentries);
                        for (TxItems::reverse_iterator it = txOrdered.rbegin(); it != txOrdered.rend(); ++it)
                        {
                            CWalletTx *const pwtx = (*it).second.first;
                            if (pwtx == &wtx)
                                continue;
                            CAccountingEntry *const pacentry = (*it).second.second;
                            int64 nSmartTime;
                            if (pwtx)
                            {
                                nSmartTime = pwtx->nTimeSmart;
                                if (!nSmartTime)
                                    nSmartTime = pwtx->nTimeReceived;
                            }
                            else
                                nSmartTime = pacentry->nTime;
                            if (nSmartTime <= latestTolerated)
                            {
                                latestEntry = nSmartTime;
                                if (nSmartTime > latestNow)
                                    latestNow = nSmartTime;
                                break;
                            }
                        }
                    }

                    unsigned int& blocktime = mapBlockIndex[wtxIn.hashBlock]->nTime;
                    wtx.nTimeSmart = std::max(latestEntry, std::min(blocktime, latestNow));
                }
                else
                    printf("AddToWallet() : found %s in block %s not in index\n",
                           wtxIn.GetHash().ToString().c_str(),
                           wtxIn.hashBlock.ToString().c_str());
            }
        }

        bool fUpdated = false;
        if (!fInsertedNew)
        {
            // Merge
            if (wtxIn.hashBlock != 0 && wtxIn.hashBlock != wtx.hashBlock)
            {
                wtx.hashBlock = wtxIn.hashBlock;
                fUpdated = true;
            }
            if (wtxIn.nIndex != -1 && (wtxIn.vMerkleBranch != wtx.vMerkleBranch || wtxIn.nIndex != wtx.nIndex))
            {
                wtx.vMerkleBranch = wtxIn.vMerkleBranch;
                wtx.nIndex = wtxIn.nIndex;
                fUpdated = true;
            }
            if (wtxIn.fFromMe && wtxIn.fFromMe != wtx.fFromMe)
            {
                wtx.fFromMe = wtxIn.fFromMe;
                fUpdated = true;
            }
            fUpdated |= wtx.UpdateSpent(wtxIn.vfSpent);
        }

        //// debug print
        printf("AddToWallet %s  %s%s\n", wtxIn.GetHash().ToString().c_str(), (fInsertedNew ? "new" : ""), (fUpdated ? "update" : ""));

        // Write to disk
        if (fInsertedNew || fUpdated)
            if (!wtx.WriteToDisk())
                return false;
#ifndef QT_GUI
        // If default receiving address gets used, replace it with a new one
        if (vchDefaultKey.IsValid()) {
            CScript scriptDefaultKey;
            scriptDefaultKey.SetDestination(vchDefaultKey.GetID());
            BOOST_FOREACH(const CTxOut& txout, wtx.vout)
            {
                if (txout.scriptPubKey == scriptDefaultKey)
                {
                    CPubKey newDefaultKey;
                    if (GetKeyFromPool(newDefaultKey, false))
                    {
                        SetDefaultKey(newDefaultKey);
                        SetAddressBookName(vchDefaultKey.GetID(), "");
                    }
                }
            }
        }
#endif
        // since AddToWallet is called directly for self-originating transactions, check for consumption of own coins
        WalletUpdateSpent(wtx);

        // Notify UI of new or updated transaction
        NotifyTransactionChanged(this, hash, fInsertedNew ? CT_NEW : CT_UPDATED);

        // notify an external script when a wallet transaction comes in or is updated
        std::string strCmd = GetArg("-walletnotify", "");

        if ( !strCmd.empty())
        {
            boost::replace_all(strCmd, "%s", wtxIn.GetHash().GetHex());
            boost::thread t(runCommand, strCmd); // thread runs free
        }

    }
    return true;
}

// Add a transaction to the wallet, or update it.
// pblock is optional, but should be provided if the transaction is known to be in a block.
// If fUpdate is true, existing transactions will be updated.
bool CWallet::AddToWalletIfInvolvingMe(const uint256 &hash, const CTransaction& tx, const CBlock* pblock, bool fUpdate, bool fFindBlock)
{
    {
        LOCK(cs_wallet);
        bool fExisted = mapWallet.count(hash);
        if (fExisted && !fUpdate) return false;
        if (fExisted || IsMine(tx) || IsFromMe(tx))
        {
            CWalletTx wtx(this,tx);
            // Get merkle branch if transaction was found in a block
            if (pblock)
                wtx.SetMerkleBranch(pblock);
            return AddToWallet(wtx);
        }
        else
            WalletUpdateSpent(tx);
    }
    return false;
}

bool CWallet::EraseFromWallet(uint256 hash)
{
    if (!fFileBacked)
        return false;
    {
        LOCK(cs_wallet);
        if (mapWallet.erase(hash))
            CWalletDB(strWalletFile).EraseTx(hash);
    }
    return true;
}


bool CWallet::IsMine(const CTxIn &txin) const
{
    {
        LOCK(cs_wallet);
        map<uint256, CWalletTx>::const_iterator mi = mapWallet.find(txin.prevout.hash);
        if (mi != mapWallet.end())
        {
            const CWalletTx& prev = (*mi).second;
            if (txin.prevout.n < prev.vout.size())
                if (IsMine(prev.vout[txin.prevout.n]))
                    return true;
        }
    }
    return false;
}

int64 CWallet::GetDebit(const CTxIn &txin) const
{
    {
        LOCK(cs_wallet);
        map<uint256, CWalletTx>::const_iterator mi = mapWallet.find(txin.prevout.hash);
        if (mi != mapWallet.end())
        {
            const CWalletTx& prev = (*mi).second;
            if (txin.prevout.n < prev.vout.size())
                if (IsMine(prev.vout[txin.prevout.n]))
                    return prev.vout[txin.prevout.n].nValue;
        }
    }
    return 0;
}

bool CWallet::IsDenominated(const CTxIn &txin) const
{
	{
		LOCK(cs_wallet);
		map<uint256, CWalletTx>::const_iterator mi = mapWallet.find(txin.prevout.hash);
		if (mi != mapWallet.end())
		{
			const CWalletTx& prev = (*mi).second;
			if (txin.prevout.n < prev.vout.size()) return IsDenominatedAmount(prev.vout[txin.prevout.n].nValue);
		}
	}
	return false;
}

bool CWallet::IsDenominatedAmount(int64_t nInputAmount) const
{
	BOOST_FOREACH(int64_t d, darkSendDenominations)
		if (nInputAmount == d)
			return true;
	return false;
}


bool CWallet::IsChange(const CTxOut& txout) const
{
    CTxDestination address;

    // TODO: fix handling of 'change' outputs. The assumption is that any
    // payment to a TX_PUBKEYHASH that is mine but isn't in the address book
    // is change. That assumption is likely to break when we implement multisignature
    // wallets that return change back into a multi-signature-protected address;
    // a better way of identifying which outputs are 'the send' and which are
    // 'the change' will need to be implemented (maybe extend CWalletTx to remember
    // which output, if any, was change).
    if (ExtractDestination(txout.scriptPubKey, address) && ::IsMine(*this, address))
    {
        LOCK(cs_wallet);
        if (!mapAddressBook.count(address))
            return true;
    }
    return false;
}

int64 CWalletTx::GetTxTime() const
{
    int64 n = nTimeSmart;
    return n ? n : nTimeReceived;
}

int CWalletTx::GetRequestCount() const
{
    // Returns -1 if it wasn't being tracked
    int nRequests = -1;
    {
        LOCK(pwallet->cs_wallet);
        if (IsCoinBase())
        {
            // Generated block
            if (hashBlock != 0)
            {
                map<uint256, int>::const_iterator mi = pwallet->mapRequestCount.find(hashBlock);
                if (mi != pwallet->mapRequestCount.end())
                    nRequests = (*mi).second;
            }
        }
        else
        {
            // Did anyone request this transaction?
            map<uint256, int>::const_iterator mi = pwallet->mapRequestCount.find(GetHash());
            if (mi != pwallet->mapRequestCount.end())
            {
                nRequests = (*mi).second;

                // How about the block it's in?
                if (nRequests == 0 && hashBlock != 0)
                {
                    map<uint256, int>::const_iterator mi = pwallet->mapRequestCount.find(hashBlock);
                    if (mi != pwallet->mapRequestCount.end())
                        nRequests = (*mi).second;
                    else
                        nRequests = 1; // If it's in someone else's block it must have got out
                }
            }
        }
    }
    return nRequests;
}

void CWalletTx::GetAmounts(list<pair<CTxDestination, int64> >& listReceived,
                           list<pair<CTxDestination, int64> >& listSent, int64& nFee, string& strSentAccount) const
{
    nFee = 0;
    listReceived.clear();
    listSent.clear();
    strSentAccount = strFromAccount;

    // Compute fee:
    int64 nDebit = GetDebit();
    if (nDebit > 0) // debit>0 means we signed/sent this transaction
    {
        int64 nValueOut = GetValueOut();
        nFee = nDebit - nValueOut;
    }

    // Sent/received.
    BOOST_FOREACH(const CTxOut& txout, vout)
    {
        bool fIsMine;
        // Only need to handle txouts if AT LEAST one of these is true:
        //   1) they debit from us (sent)
        //   2) the output is to us (received)
        if (nDebit > 0)
        {
            // Don't report 'change' txouts
            if (pwallet->IsChange(txout))
                continue;
            fIsMine = pwallet->IsMine(txout);
        }
        else if (!(fIsMine = pwallet->IsMine(txout)))
            continue;

        // In either case, we need to get the destination address
        CTxDestination address;
        if (!ExtractDestination(txout.scriptPubKey, address))
        {
            printf("CWalletTx::GetAmounts: Unknown transaction type found, txid %s\n",
                   this->GetHash().ToString().c_str());
            address = CNoDestination();
        }

        // If we are debited by the transaction, add the output as a "sent" entry
        if (nDebit > 0)
            listSent.push_back(make_pair(address, txout.nValue));

        // If we are receiving the output, add it as a "received" entry
        if (fIsMine)
            listReceived.push_back(make_pair(address, txout.nValue));
    }

}

void CWalletTx::GetAccountAmounts(const string& strAccount, int64& nReceived,
                                  int64& nSent, int64& nFee) const
{
    nReceived = nSent = nFee = 0;

    int64 allFee;
    string strSentAccount;
    list<pair<CTxDestination, int64> > listReceived;
    list<pair<CTxDestination, int64> > listSent;
    GetAmounts(listReceived, listSent, allFee, strSentAccount);

    if (strAccount == strSentAccount)
    {
        BOOST_FOREACH(const PAIRTYPE(CTxDestination,int64)& s, listSent)
            nSent += s.second;
        nFee = allFee;
    }
    {
        LOCK(pwallet->cs_wallet);
        BOOST_FOREACH(const PAIRTYPE(CTxDestination,int64)& r, listReceived)
        {
            if (pwallet->mapAddressBook.count(r.first))
            {
                map<CTxDestination, string>::const_iterator mi = pwallet->mapAddressBook.find(r.first);
                if (mi != pwallet->mapAddressBook.end() && (*mi).second == strAccount)
                    nReceived += r.second;
            }
            else if (strAccount.empty())
            {
                nReceived += r.second;
            }
        }
    }
}

void CWalletTx::AddSupportingTransactions()
{
    vtxPrev.clear();

    const int COPY_DEPTH = 3;
    if (SetMerkleBranch() < COPY_DEPTH)
    {
        vector<uint256> vWorkQueue;
        BOOST_FOREACH(const CTxIn& txin, vin)
            vWorkQueue.push_back(txin.prevout.hash);

        {
            LOCK(pwallet->cs_wallet);
            map<uint256, const CMerkleTx*> mapWalletPrev;
            set<uint256> setAlreadyDone;
            for (unsigned int i = 0; i < vWorkQueue.size(); i++)
            {
                uint256 hash = vWorkQueue[i];
                if (setAlreadyDone.count(hash))
                    continue;
                setAlreadyDone.insert(hash);

                CMerkleTx tx;
                map<uint256, CWalletTx>::const_iterator mi = pwallet->mapWallet.find(hash);
                if (mi != pwallet->mapWallet.end())
                {
                    tx = (*mi).second;
                    BOOST_FOREACH(const CMerkleTx& txWalletPrev, (*mi).second.vtxPrev)
                        mapWalletPrev[txWalletPrev.GetHash()] = &txWalletPrev;
                }
                else if (mapWalletPrev.count(hash))
                {
                    tx = *mapWalletPrev[hash];
                }
                else
                {
                    continue;
                }

                int nDepth = tx.SetMerkleBranch();
                vtxPrev.push_back(tx);

                if (nDepth < COPY_DEPTH)
                {
                    BOOST_FOREACH(const CTxIn& txin, tx.vin)
                        vWorkQueue.push_back(txin.prevout.hash);
                }
            }
        }
    }

    reverse(vtxPrev.begin(), vtxPrev.end());
}

bool CWalletTx::WriteToDisk()
{
    return CWalletDB(pwallet->strWalletFile).WriteTx(GetHash(), *this);
}

// Scan the block chain (starting in pindexStart) for transactions
// from or to us. If fUpdate is true, found transactions that already
// exist in the wallet will be updated.
int CWallet::ScanForWalletTransactions(CBlockIndex* pindexStart, bool fUpdate)
{
    int ret = 0;

    CBlockIndex* pindex = pindexStart;
    {
        LOCK(cs_wallet);
        while (pindex)
        {
            CBlock block;
            block.ReadFromDisk(pindex);
            BOOST_FOREACH(CTransaction& tx, block.vtx)
            {
                if (AddToWalletIfInvolvingMe(tx.GetHash(), tx, &block, fUpdate))
                    ret++;
            }
            pindex = pindex->pnext;
        }
    }
    return ret;
}

void CWallet::ReacceptWalletTransactions()
{
    bool fRepeat = true;
    while (fRepeat)
    {
        LOCK(cs_wallet);
        fRepeat = false;
        bool fMissing = false;
        BOOST_FOREACH(PAIRTYPE(const uint256, CWalletTx)& item, mapWallet)
        {
            CWalletTx& wtx = item.second;
            if (wtx.IsCoinBase() && wtx.IsSpent(0))
                continue;

            CCoins coins;
            bool fUpdated = false;
            bool fFound = pcoinsTip->GetCoins(wtx.GetHash(), coins);
            if (fFound || wtx.GetDepthInMainChain() > 0)
            {
                // Update fSpent if a tx got spent somewhere else by a copy of wallet.dat
                for (unsigned int i = 0; i < wtx.vout.size(); i++)
                {
                    if (wtx.IsSpent(i))
                        continue;
                    if ((i >= coins.vout.size() || coins.vout[i].IsNull()) && IsMine(wtx.vout[i]))
                    {
                        wtx.MarkSpent(i);
                        fUpdated = true;
                        fMissing = true;
                    }
                }
                if (fUpdated)
                {
                    printf("ReacceptWalletTransactions found spent coin %sbc %s\n", FormatMoney(wtx.GetCredit()).c_str(), wtx.GetHash().ToString().c_str());
                    wtx.MarkDirty();
                    wtx.WriteToDisk();
                }
            }
            else
            {
                // Re-accept any txes of ours that aren't already in a block
                if (!wtx.IsCoinBase())
                    wtx.AcceptWalletTransaction(false);
            }
        }
        if (fMissing)
        {
            // TODO: optimize this to scan just part of the block chain?
            if (ScanForWalletTransactions(pindexGenesisBlock))
                fRepeat = true;  // Found missing transactions: re-do re-accept.
        }
    }
}

void CWalletTx::RelayWalletTransaction()
{
    BOOST_FOREACH(const CMerkleTx& tx, vtxPrev)
    {
        // Important: versions of bitcoin before 0.8.6 had a bug that inserted
        // empty transactions into the vtxPrev, which will cause the node to be
        // banned when retransmitted, hence the check for !tx.vin.empty()
        if (!tx.IsCoinBase() && !tx.vin.empty())
            if (tx.GetDepthInMainChain() == 0)
                RelayTransaction((CTransaction)tx, tx.GetHash());
    }
    if (!IsCoinBase())
    {
        if (GetDepthInMainChain() == 0) {
            uint256 hash = GetHash();
            printf("Relaying wtx %s\n", hash.ToString().c_str());
            RelayTransaction((CTransaction)*this, hash);
        }
    }
}

void CWallet::ResendWalletTransactions()
{
    // Do this infrequently and randomly to avoid giving away
    // that these are our transactions.
    static int64 nNextTime;
    if (GetTime() < nNextTime)
        return;
    bool fFirst = (nNextTime == 0);
    nNextTime = GetTime() + GetRand(30 * 60);
    if (fFirst)
        return;

    // Only do it if there's been a new block since last time
    static int64 nLastTime;
    if (nTimeBestReceived < nLastTime)
        return;
    nLastTime = GetTime();

    // Rebroadcast any of our txes that aren't in a block yet
    printf("ResendWalletTransactions()\n");
    {
        LOCK(cs_wallet);
        // Sort them in chronological order
        multimap<unsigned int, CWalletTx*> mapSorted;
        BOOST_FOREACH(PAIRTYPE(const uint256, CWalletTx)& item, mapWallet)
        {
            CWalletTx& wtx = item.second;
            // Don't rebroadcast until it's had plenty of time that
            // it should have gotten in already by now.
            if (nTimeBestReceived - (int64)wtx.nTimeReceived > 5 * 60)
                mapSorted.insert(make_pair(wtx.nTimeReceived, &wtx));
        }
        BOOST_FOREACH(PAIRTYPE(const unsigned int, CWalletTx*)& item, mapSorted)
        {
            CWalletTx& wtx = *item.second;
            wtx.RelayWalletTransaction();
        }
    }
}






//////////////////////////////////////////////////////////////////////////////
//
// Actions
//


int64 CWallet::GetBalance() const
{
    int64 nTotal = 0;
    {
        LOCK(cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx* pcoin = &(*it).second;
            if (pcoin->IsConfirmed())
                nTotal += pcoin->GetAvailableCredit();
        }
    }

    return nTotal;
}

int64 CWallet::GetUnconfirmedBalance() const
{
    int64 nTotal = 0;
    {
        LOCK(cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx* pcoin = &(*it).second;
            if (!pcoin->IsFinal() || !pcoin->IsConfirmed())
                nTotal += pcoin->GetAvailableCredit();
        }
    }
    return nTotal;
}

CAmount CWallet::GetAnonymizedBalance() const
{
	int64_t nTotal = 0;
	{
		LOCK(cs_wallet);
		for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
		{
			const CWalletTx* pcoin = &(*it).second;

			if (pcoin->IsTrusted())
			{
				int nDepth = pcoin->GetDepthInMainChain();

				for (unsigned int i = 0; i < pcoin->vout.size(); i++) {
					//isminetype mine = IsMine(pcoin->vout[i]);
					bool mine = IsMine(pcoin->vout[i]);
					//COutput out = COutput(pcoin, i, nDepth, (mine & ISMINE_SPENDABLE) != ISMINE_NO);
					COutput out = COutput(pcoin, i, nDepth, mine);
					CTxIn vin = CTxIn(out.tx->GetHash(), out.i);

					//if(IsSpent(out.tx->GetHash(), i) || !IsMine(pcoin->vout[i]) || !IsDenominated(vin)) continue;	
					if (pcoin->IsSpent(i) || !IsMine(pcoin->vout[i]) || !IsDenominated(vin)) continue;

					int rounds = GetInputDarksendRounds(vin);
					if (rounds >= nDarksendRounds) {
						nTotal += pcoin->vout[i].nValue;
					}
				}
			}
		}
	}

	return nTotal;
}

double CWallet::GetAverageAnonymizedRounds() const
{
	double fTotal = 0;
	double fCount = 0;

	{
		LOCK(cs_wallet);
		for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
		{
			const CWalletTx* pcoin = &(*it).second;

			if (pcoin->IsTrusted())
			{
				int nDepth = pcoin->GetDepthInMainChain();

				for (unsigned int i = 0; i < pcoin->vout.size(); i++) {
					//isminetype mine = IsMine(pcoin->vout[i]);
					bool mine = IsMine(pcoin->vout[i]);
					//COutput out = COutput(pcoin, i, nDepth, (mine & ISMINE_SPENDABLE) != ISMINE_NO);
					COutput out = COutput(pcoin, i, nDepth, mine);
					CTxIn vin = CTxIn(out.tx->GetHash(), out.i);

					//if(IsSpent(out.tx->GetHash(), i) || !IsMine(pcoin->vout[i]) || !IsDenominated(vin)) continue;
					if (pcoin->IsSpent(i) || !IsMine(pcoin->vout[i]) || !IsDenominated(vin)) continue;

					int rounds = GetInputDarksendRounds(vin);
					fTotal += (float)rounds;
					fCount += 1;
				}
			}
		}
	}

	if (fCount == 0) return 0;

	return fTotal / fCount;
}

CAmount CWallet::GetNormalizedAnonymizedBalance() const
{
	int64_t nTotal = 0;

	{
		LOCK(cs_wallet);
		for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
		{
			const CWalletTx* pcoin = &(*it).second;

			if (pcoin->IsTrusted())
			{
				int nDepth = pcoin->GetDepthInMainChain();

				for (unsigned int i = 0; i < pcoin->vout.size(); i++) {
					//isminetype mine = IsMine(pcoin->vout[i]);
					bool mine = IsMine(pcoin->vout[i]);
					//COutput out = COutput(pcoin, i, nDepth, (mine & ISMINE_SPENDABLE) != ISMINE_NO);
					COutput out = COutput(pcoin, i, nDepth, mine);
					CTxIn vin = CTxIn(out.tx->GetHash(), out.i);

					//if(IsSpent(out.tx->GetHash(), i) || !IsMine(pcoin->vout[i]) || !IsDenominated(vin)) continue;
					if (pcoin->IsSpent(i) || !IsMine(pcoin->vout[i]) || !IsDenominated(vin)) continue;

					int rounds = GetInputDarksendRounds(vin);
					nTotal += pcoin->vout[i].nValue * rounds / nDarksendRounds;
				}
			}
		}
	}

	return nTotal;
}

CAmount CWallet::GetDenominatedBalance(bool onlyDenom, bool onlyUnconfirmed) const
{
	int64_t nTotal = 0;
	{
		LOCK(cs_wallet);
		for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
		{
			const CWalletTx* pcoin = &(*it).second;

			int nDepth = pcoin->GetDepthInMainChain();

			// skip conflicted
			if (nDepth < 0) continue;

			bool unconfirmed = (!IsFinalTx(*pcoin) || (!pcoin->IsTrusted() && nDepth == 0));
			if (onlyUnconfirmed != unconfirmed) continue;

			for (unsigned int i = 0; i < pcoin->vout.size(); i++)
			{
				//isminetype mine = IsMine(pcoin->vout[i]);
				//bool mine = IsMine(pcoin->vout[i]);
				//COutput out = COutput(pcoin, i, nDepth, (mine & ISMINE_SPENDABLE) != ISMINE_NO);
				//COutput out = COutput(pcoin, i, nDepth, mine);

				//if(IsSpent(out.tx->GetHash(), i)) continue;
				if (pcoin->IsSpent(i)) continue;
				if (!IsMine(pcoin->vout[i])) continue;
				if (onlyDenom != IsDenominatedAmount(pcoin->vout[i].nValue)) continue;

				nTotal += pcoin->vout[i].nValue;
			}
		}
	}



	return nTotal;
}

int64 CWallet::GetImmatureBalance() const
{
    int64 nTotal = 0;
    {
        LOCK(cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx* pcoin = &(*it).second;
            nTotal += pcoin->GetImmatureCredit();
        }
    }
    return nTotal;
}

// populate vCoins with vector of spendable COutputs
void CWallet::AvailableCoins(vector<COutput>& vCoins, bool fOnlyConfirmed, const CCoinControl *coinControl) const
{
    vCoins.clear();

    {
        LOCK(cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx* pcoin = &(*it).second;

            if (!pcoin->IsFinal())
                continue;

            if (fOnlyConfirmed && !pcoin->IsConfirmed())
                continue;

            if (pcoin->IsCoinBase() && pcoin->GetBlocksToMaturity() > 0)
                continue;

            int nDepth = pcoin->GetDepthInMainChain();
            if (nDepth < 0)
                continue;

            for (unsigned int i = 0; i < pcoin->vout.size(); i++) {
                if (!(pcoin->IsSpent(i)) && IsMine(pcoin->vout[i]) &&
                    !IsLockedCoin((*it).first, i) && pcoin->vout[i].nValue >= nMinimumInputValue &&
                    (!coinControl || !coinControl->HasSelected() || coinControl->IsSelected((*it).first, i))) 
                    vCoins.push_back(COutput(pcoin, i, nDepth));
            }
        }
    }
}

void CWallet::AvailableCoinsDeno(vector<COutput>& vCoins, bool fOnlyConfirmed, const CCoinControl *coinControl, AvailableCoinsType coin_type, bool useIX) const
{
	vCoins.clear();

	{
		LOCK2(cs_main, cs_wallet);
		for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
		{
			const CWalletTx* pcoin = &(*it).second;

			if (!IsFinalTx(*pcoin))
				continue;

			if (fOnlyConfirmed && !pcoin->IsTrusted())
				continue;

			if (pcoin->IsCoinBase() && pcoin->GetBlocksToMaturity() > 0)
				continue;

			/*if (pcoin->IsCoinStake() && pcoin->GetBlocksToMaturity() > 0)
				continue;*/

			int nDepth = pcoin->GetDepthInMainChain();
			if (nDepth <= 0) // ScoreNOTE: coincontrol fix / ignore 0 confirm 
				continue;

			/* for (unsigned int i = 0; i < pcoin->vout.size(); i++)
			if (!(pcoin->IsSpent(i)) && IsMine(pcoin->vout[i]) && pcoin->vout[i].nValue >= nMinimumInputValue &&
			(!coinControl || !coinControl->HasSelected() || coinControl->IsSelected((*it).first, i)))
			vCoins.push_back(COutput(pcoin, i, nDepth));*/
			// do not use IX for inputs that have less then 6 blockchain confirmations
			if (useIX && nDepth < 6)
				continue;

			for (unsigned int i = 0; i < pcoin->vout.size(); i++) {
				bool found = false;
				if (coin_type == ONLY_DENOMINATED) {
					//should make this a vector

					found = IsDenominatedAmount(pcoin->vout[i].nValue);
				}
				else if (coin_type == ONLY_NONDENOMINATED || coin_type == ONLY_NONDENOMINATED_NOTMN) {
					found = true;
					if (IsCollateralAmount(pcoin->vout[i].nValue)) continue; // do not use collateral amounts
					found = !IsDenominatedAmount(pcoin->vout[i].nValue);
					if (found && coin_type == ONLY_NONDENOMINATED_NOTMN) found = (pcoin->vout[i].nValue != 500 * COIN); // do not use MN funds
				}
				else {
					found = true;
				}
				if (!found) continue;

				//isminetype mine = IsMine(pcoin->vout[i]);
				bool mine = IsMine(pcoin->vout[i]);

				//if (!(IsSpent(wtxid, i)) && mine != ISMINE_NO &&
				//    !IsLockedCoin((*it).first, i) && pcoin->vout[i].nValue > 0 &&
				//    (!coinControl || !coinControl->HasSelected() || coinControl->IsSelected((*it).first, i)))
				//        vCoins.push_back(COutput(pcoin, i, nDepth, (mine & ISMINE_SPENDABLE) != ISMINE_NO));
				//if (!(IsSpent(wtxid, i)) && mine &&
				if (!(pcoin->IsSpent(i)) && mine &&
					!IsLockedCoin((*it).first, i) && pcoin->vout[i].nValue > 0 &&
					(!coinControl || !coinControl->HasSelected() || coinControl->IsSelected((*it).first, i)))
					vCoins.push_back(COutput(pcoin, i, nDepth, mine));
			}
		}
	}
}


static void ApproximateBestSubset(vector<pair<int64, pair<const CWalletTx*,unsigned int> > >vValue, int64 nTotalLower, int64 nTargetValue,
                                  vector<char>& vfBest, int64& nBest, int iterations = 1000)
{
    vector<char> vfIncluded;

    vfBest.assign(vValue.size(), true);
    nBest = nTotalLower;

    seed_insecure_rand();

    for (int nRep = 0; nRep < iterations && nBest != nTargetValue; nRep++)
    {
        vfIncluded.assign(vValue.size(), false);
        int64 nTotal = 0;
        bool fReachedTarget = false;
        for (int nPass = 0; nPass < 2 && !fReachedTarget; nPass++)
        {
            for (unsigned int i = 0; i < vValue.size(); i++)
            {
                //The solver here uses a randomized algorithm,
                //the randomness serves no real security purpose but is just
                //needed to prevent degenerate behavior and it is important
                //that the rng fast. We do not use a constant random sequence,
                //because there may be some privacy improvement by making
                //the selection random.
                if (nPass == 0 ? insecure_rand()&1 : !vfIncluded[i])
                {
                    nTotal += vValue[i].first;
                    vfIncluded[i] = true;
                    if (nTotal >= nTargetValue)
                    {
                        fReachedTarget = true;
                        if (nTotal < nBest)
                        {
                            nBest = nTotal;
                            vfBest = vfIncluded;
                        }
                        nTotal -= vValue[i].first;
                        vfIncluded[i] = false;
                    }
                }
            }
        }
    }
}

struct LargerOrEqualThanThreshold
{
	int64_t threshold;
	LargerOrEqualThanThreshold(int64_t threshold) : threshold(threshold) {}
	bool operator()(pair<pair<int64_t, int64_t>, pair<const CWalletTx*, unsigned int> > const &v) const { return v.first.first >= threshold; }
};

bool CWallet::SelectCoinsMinConfByCoinAge(int64_t nTargetValue, unsigned int nSpendTime, int nConfMine, int nConfTheirs, std::vector<COutput> vCoins, set<pair<const CWalletTx*, unsigned int> >& setCoinsRet, int64_t& nValueRet) const
{
	setCoinsRet.clear();
	nValueRet = 0;

	vector<pair<COutput, uint64_t> > mCoins;
	BOOST_FOREACH(const COutput& out, vCoins)
	{
		mCoins.push_back(std::make_pair(out, CoinWeightCost(out)));
	}

	// List of values less than target
	pair<pair<int64_t, int64_t>, pair<const CWalletTx*, unsigned int> > coinLowestLarger;
	coinLowestLarger.first.second = std::numeric_limits<int64_t>::max();
	coinLowestLarger.second.first = NULL;
	vector<pair<pair<int64_t, int64_t>, pair<const CWalletTx*, unsigned int> > > vValue;
	int64_t nTotalLower = 0;
	boost::sort(mCoins, boost::bind(&std::pair<COutput, uint64_t>::second, _1) < boost::bind(&std::pair<COutput, uint64_t>::second, _2));

	BOOST_FOREACH(const PAIRTYPE(COutput, uint64_t)& output, mCoins)
	{
		const CWalletTx *pcoin = output.first.tx;

		if (output.first.nDepth < (pcoin->IsFromMe() ? nConfMine : nConfTheirs))
			continue;

		int i = output.first.i;

		// Follow the timestamp rules
		if (pcoin->nTime > nSpendTime)
			continue;

		int64_t n = pcoin->vout[i].nValue;

		pair<pair<int64_t, int64_t>, pair<const CWalletTx*, unsigned int> > coin = make_pair(make_pair(n, output.second), make_pair(pcoin, i));

		if (n < nTargetValue + CENT)
		{
			vValue.push_back(coin);
			nTotalLower += n;
		}
		else if (output.second < (uint64_t)coinLowestLarger.first.second)
		{
			coinLowestLarger = coin;
		}
	}

	if (nTotalLower < nTargetValue)
	{
		if (coinLowestLarger.second.first == NULL)
			return false;
		setCoinsRet.insert(coinLowestLarger.second);
		nValueRet += coinLowestLarger.first.first;
		return true;
	}

	// Calculate dynamic programming matrix
	int64_t nTotalValue = vValue[0].first.first;
	int64_t nGCD = vValue[0].first.first;
	for (unsigned int i = 1; i < vValue.size(); ++i)
	{
		nGCD = gcd(vValue[i].first.first, nGCD);
		nTotalValue += vValue[i].first.first;
	}
	nGCD = gcd(nTargetValue, nGCD);
	int64_t denom = nGCD;
	const int64_t k = 25;
	const int64_t approx = int64_t(vValue.size() * (nTotalValue - nTargetValue)) / k;
	if (approx > nGCD)
	{
		denom = approx; // apply approximation
	}
	if (fDebug) cerr << "nGCD " << nGCD << " denom " << denom << " k " << k << endl;

	if (nTotalValue == nTargetValue)
	{
		for (unsigned int i = 0; i < vValue.size(); ++i)
		{
			setCoinsRet.insert(vValue[i].second);
		}
		nValueRet = nTotalValue;
		return true;
	}

	size_t nBeginBundles = vValue.size();
	size_t nTotalCoinValues = vValue.size();
	size_t nBeginCoinValues = 0;
	int64_t costsum = 0;
	vector<vector<pair<pair<int64_t, int64_t>, pair<const CWalletTx*, unsigned int> > >::iterator> vZeroValueBundles;
	if (denom != nGCD)
	{
		// All coin outputs that with zero value will always be added by the dynamic programming routine
		// So we collect them into bundles of value denom
		vector<pair<pair<int64_t, int64_t>, pair<const CWalletTx*, unsigned int> > >::iterator itZeroValue = std::stable_partition(vValue.begin(), vValue.end(), LargerOrEqualThanThreshold(denom));
		vZeroValueBundles.push_back(itZeroValue);
		pair<int64_t, int64_t> pBundle = make_pair(0, 0);
		nBeginBundles = itZeroValue - vValue.begin();
		nTotalCoinValues = nBeginBundles;
		while (itZeroValue != vValue.end())
		{
			pBundle.first += itZeroValue->first.first;
			pBundle.second += itZeroValue->first.second;
			itZeroValue++;
			if (pBundle.first >= denom)
			{
				vZeroValueBundles.push_back(itZeroValue);
				vValue[nTotalCoinValues].first = pBundle;
				pBundle = make_pair(0, 0);
				nTotalCoinValues++;
			}
		}
		// We need to recalculate the total coin value due to truncation of integer division
		nTotalValue = 0;
		for (unsigned int i = 0; i < nTotalCoinValues; ++i)
		{
			nTotalValue += vValue[i].first.first / denom;
		}
		// Check if dynamic programming is still applicable with the approximation
		if (nTargetValue / denom >= nTotalValue)
		{
			// We lose too much coin value through the approximation, i.e. the residual of the previous recalculation is too large
			// Since the partitioning of the previously sorted list is stable, we can just pick the first coin outputs in the list until we have a valid target value
			for (; nBeginCoinValues < nTotalCoinValues && (nTargetValue - nValueRet) / denom >= nTotalValue; ++nBeginCoinValues)
			{
				if (nBeginCoinValues >= nBeginBundles)
				{
					if (fDebug) cerr << "prepick bundle item " << FormatMoney(vValue[nBeginCoinValues].first.first) << " normalized " << vValue[nBeginCoinValues].first.first / denom << " cost " << vValue[nBeginCoinValues].first.second << endl;
					const size_t nBundle = nBeginCoinValues - nBeginBundles;
					for (vector<pair<pair<int64_t, int64_t>, pair<const CWalletTx*, unsigned int> > >::iterator it = vZeroValueBundles[nBundle]; it != vZeroValueBundles[nBundle + 1]; ++it)
					{
						setCoinsRet.insert(it->second);
					}
				}
				else
				{
					if (fDebug) cerr << "prepicking " << FormatMoney(vValue[nBeginCoinValues].first.first) << " normalized " << vValue[nBeginCoinValues].first.first / denom << " cost " << vValue[nBeginCoinValues].first.second << endl;
					setCoinsRet.insert(vValue[nBeginCoinValues].second);
				}
				nTotalValue -= vValue[nBeginCoinValues].first.first / denom;
				nValueRet += vValue[nBeginCoinValues].first.first;
				costsum += vValue[nBeginCoinValues].first.second;
			}
			if (nValueRet >= nTargetValue)
			{
				if (fDebug) cerr << "Done without dynprog: " << "requested " << FormatMoney(nTargetValue) << "\tnormalized " << nTargetValue / denom + (nTargetValue % denom != 0 ? 1 : 0) << "\tgot " << FormatMoney(nValueRet) << "\tcost " << costsum << endl;
				return true;
			}
		}
	}
	else
	{
		nTotalValue /= denom;
	}

	uint64_t nAppend = 1;
	if ((nTargetValue - nValueRet) % denom != 0)
	{
		// We need to decrease the capacity because of integer truncation
		nAppend--;
	}

	// The capacity (number of columns) corresponds to the amount of coin value we are allowed to discard
	boost::numeric::ublas::matrix<uint64_t> M((nTotalCoinValues - nBeginCoinValues) + 1, (nTotalValue - (nTargetValue - nValueRet) / denom) + nAppend, std::numeric_limits<int64_t>::max());
	boost::numeric::ublas::matrix<unsigned int> B((nTotalCoinValues - nBeginCoinValues) + 1, (nTotalValue - (nTargetValue - nValueRet) / denom) + nAppend);
	for (unsigned int j = 0; j < M.size2(); ++j)
	{
		M(0, j) = 0;
	}
	for (unsigned int i = 1; i < M.size1(); ++i)
	{
		uint64_t nWeight = vValue[nBeginCoinValues + i - 1].first.first / denom;
		uint64_t nValue = vValue[nBeginCoinValues + i - 1].first.second;
		//cerr << "Weight " << nWeight << " Value " << nValue << endl;
		for (unsigned int j = 0; j < M.size2(); ++j)
		{
			B(i, j) = j;
			if (nWeight <= j)
			{
				uint64_t nStep = M(i - 1, j - nWeight) + nValue;
				if (M(i - 1, j) >= nStep)
				{
					M(i, j) = M(i - 1, j);
				}
				else
				{
					M(i, j) = nStep;
					B(i, j) = j - nWeight;
				}
			}
			else
			{
				M(i, j) = M(i - 1, j);
			}
		}
	}
	// Trace back optimal solution
	int64_t nPrev = M.size2() - 1;
	for (unsigned int i = M.size1() - 1; i > 0; --i)
	{
		//cerr << i - 1 << " " << vValue[i - 1].second.second << " " << vValue[i - 1].first.first << " " << vValue[i - 1].first.second << " " << nTargetValue << " " << nPrev << " " << (nPrev == B(i, nPrev) ? "XXXXXXXXXXXXXXX" : "") << endl;
		if (nPrev == B(i, nPrev))
		{
			const size_t nValue = nBeginCoinValues + i - 1;
			// Check if this is a bundle
			if (nValue >= nBeginBundles)
			{
				if (fDebug) cerr << "pick bundle item " << FormatMoney(vValue[nValue].first.first) << " normalized " << vValue[nValue].first.first / denom << " cost " << vValue[nValue].first.second << endl;
				const size_t nBundle = nValue - nBeginBundles;
				for (vector<pair<pair<int64_t, int64_t>, pair<const CWalletTx*, unsigned int> > >::iterator it = vZeroValueBundles[nBundle]; it != vZeroValueBundles[nBundle + 1]; ++it)
				{
					setCoinsRet.insert(it->second);
				}
			}
			else
			{
				if (fDebug) cerr << "pick " << nValue << " value " << FormatMoney(vValue[nValue].first.first) << " normalized " << vValue[nValue].first.first / denom << " cost " << vValue[nValue].first.second << endl;
				setCoinsRet.insert(vValue[nValue].second);
			}
			nValueRet += vValue[nValue].first.first;
			costsum += vValue[nValue].first.second;
		}
		nPrev = B(i, nPrev);
	}
	if (nValueRet < nTargetValue && !vZeroValueBundles.empty())
	{
		// If we get here it means that there are either not sufficient funds to pay the transaction or that there are small coin outputs left that couldn't be bundled
		// We try to fulfill the request by adding these small coin outputs
		for (vector<pair<pair<int64_t, int64_t>, pair<const CWalletTx*, unsigned int> > >::iterator it = vZeroValueBundles.back(); it != vValue.end() && nValueRet < nTargetValue; ++it)
		{
			setCoinsRet.insert(it->second);
			nValueRet += it->first.first;
		}
	}
	if (fDebug) cerr << "requested " << FormatMoney(nTargetValue) << "\tnormalized " << nTargetValue / denom + (nTargetValue % denom != 0 ? 1 : 0) << "\tgot " << FormatMoney(nValueRet) << "\tcost " << costsum << endl;
	if (fDebug) cerr << "M " << M.size1() << "x" << M.size2() << "; vValue.size() = " << vValue.size() << endl;
	return true;
}


bool CWallet::SelectCoinsMinConf(int64 nTargetValue, int nConfMine, int nConfTheirs, vector<COutput> vCoins,
                                 set<pair<const CWalletTx*,unsigned int> >& setCoinsRet, int64& nValueRet) const
{
    setCoinsRet.clear();
    nValueRet = 0;

    // List of values less than target
    pair<int64, pair<const CWalletTx*,unsigned int> > coinLowestLarger;
    coinLowestLarger.first = std::numeric_limits<int64>::max();
    coinLowestLarger.second.first = NULL;
    vector<pair<int64, pair<const CWalletTx*,unsigned int> > > vValue;
    int64 nTotalLower = 0;

    random_shuffle(vCoins.begin(), vCoins.end(), GetRandInt);

	for (unsigned int tryDenom = 0; tryDenom < 2; tryDenom++)
	{
		if (fDebug) printf("selectcoins", "tryDenom: %d\n", tryDenom);
		vValue.clear();
		nTotalLower = 0;

    BOOST_FOREACH(COutput output, vCoins)
    {
        const CWalletTx *pcoin = output.tx;

        if (output.nDepth < (pcoin->IsFromMe() ? nConfMine : nConfTheirs))
            continue;

        int i = output.i;
        int64 n = pcoin->vout[i].nValue;


		if (tryDenom == 0 && IsDenominatedAmount(n)) continue; // we don't want denom values on first run

        pair<int64,pair<const CWalletTx*,unsigned int> > coin = make_pair(n,make_pair(pcoin, i));

        if (n == nTargetValue)
        {
            setCoinsRet.insert(coin.second);
            nValueRet += coin.first;
            return true;
        }
        else if (n < nTargetValue + CENT)
        {
            vValue.push_back(coin);
            nTotalLower += n;
        }
        else if (n < coinLowestLarger.first)
        {
            coinLowestLarger = coin;
        }
    }

    if (nTotalLower == nTargetValue)
    {
        for (unsigned int i = 0; i < vValue.size(); ++i)
        {
            setCoinsRet.insert(vValue[i].second);
            nValueRet += vValue[i].first;
        }
        return true;
    }

    if (nTotalLower < nTargetValue)
    {
        if (coinLowestLarger.second.first == NULL)
            return false;
        setCoinsRet.insert(coinLowestLarger.second);
        nValueRet += coinLowestLarger.first;
        return true;
    }

    // Solve subset sum by stochastic approximation
    sort(vValue.rbegin(), vValue.rend(), CompareValueOnly());
    vector<char> vfBest;
    int64 nBest;

    ApproximateBestSubset(vValue, nTotalLower, nTargetValue, vfBest, nBest, 1000);
    if (nBest != nTargetValue && nTotalLower >= nTargetValue + CENT)
        ApproximateBestSubset(vValue, nTotalLower, nTargetValue + CENT, vfBest, nBest, 1000);

    // If we have a bigger coin and (either the stochastic approximation didn't find a good solution,
    //                                   or the next bigger coin is closer), return the bigger coin
    if (coinLowestLarger.second.first &&
        ((nBest != nTargetValue && nBest < nTargetValue + CENT) || coinLowestLarger.first <= nBest))
    {
        setCoinsRet.insert(coinLowestLarger.second);
        nValueRet += coinLowestLarger.first;
    }
    else {
        for (unsigned int i = 0; i < vValue.size(); i++)
            if (vfBest[i])
            {
                setCoinsRet.insert(vValue[i].second);
                nValueRet += vValue[i].first;
            }

        //// debug print
        printf("SelectCoins() best subset: ");
        for (unsigned int i = 0; i < vValue.size(); i++)
            if (vfBest[i])
                printf("%s ", FormatMoney(vValue[i].first).c_str());
        printf("total %s\n", FormatMoney(nBest).c_str());
    }

    return true;
}
 return false;
}


bool CWallet::SelectCoins(int64 nTargetValue, set<pair<const CWalletTx*, unsigned int> >& setCoinsRet, int64& nValueRet, const CCoinControl* coinControl) const
{
	vector<COutput> vCoins;
	AvailableCoins(vCoins, true, coinControl);

	// coin control -> return all selected outputs (we want all selected to go into the transaction for sure)
	if (coinControl && coinControl->HasSelected())
	{
		BOOST_FOREACH(const COutput& out, vCoins)
		{
			nValueRet += out.tx->vout[out.i].nValue;
			setCoinsRet.insert(make_pair(out.tx, out.i));
		}
		return (nValueRet >= nTargetValue);
	}

	return (SelectCoinsMinConf(nTargetValue, 1, 6, vCoins, setCoinsRet, nValueRet) ||
		SelectCoinsMinConf(nTargetValue, 1, 1, vCoins, setCoinsRet, nValueRet) ||
		(bSpendZeroConfChange && SelectCoinsMinConf(nTargetValue, 0, 1, vCoins, setCoinsRet, nValueRet)));
}


struct CompareByPriority
{
	bool operator()(const COutput& t1,
		const COutput& t2) const
	{
		return t1.Priority() > t2.Priority();
	}
};


bool CWallet::SelectCoinsByDenominations(int nDenom, int64_t nValueMin, int64_t nValueMax, std::vector<CTxIn>& setCoinsRet, vector<COutput>& setCoinsRet2, int64_t& nValueRet, int nDarksendRoundsMin, int nDarksendRoundsMax)
{
	setCoinsRet.clear();
	nValueRet = 0;

	setCoinsRet2.clear();
	vector<COutput> vCoins;
	AvailableCoins(vCoins);

	//order the array so fees are first, then denominated money, then the rest.
	std::random_shuffle(vCoins.rbegin(), vCoins.rend());

	//keep track of each denomination that we have
	bool fFound100000 = false;
	bool fFound10000 = false;
	bool fFound1000 = false;
	bool fFound100 = false;
	bool fFound10 = false;
	bool fFound1 = false;
	bool fFoundDot1 = false;

	//Check to see if any of the denomination are off, in that case mark them as fulfilled



	if (!(nDenom & (1 << 0))) fFound100000 = true;
	if (!(nDenom & (1 << 1))) fFound10000 = true;
	if (!(nDenom & (1 << 2))) fFound1000 = true;
	if (!(nDenom & (1 << 3))) fFound100 = true;
	if (!(nDenom & (1 << 4))) fFound10 = true;
	if (!(nDenom & (1 << 5))) fFound1 = true;
	if (!(nDenom & (1 << 6))) fFoundDot1 = true;

	BOOST_FOREACH(const COutput& out, vCoins)
	{
		//there's no reason to allow inputs less than 1 COIN into DS (other than denominations smaller than that amount)
		if (out.tx->vout[out.i].nValue < 1 * COIN && out.tx->vout[out.i].nValue != (.1*COIN) + 100) continue;
		if (fMasterNode && out.tx->vout[out.i].nValue == 250000 * COIN) continue; //masternode input
		if (nValueRet + out.tx->vout[out.i].nValue <= nValueMax) {
			bool fAccepted = false;

			// Function returns as follows:
			//
			// bit 0 - 100Score+1 ( bit on if present )
			// bit 1 - 10Score+1
			// bit 2 - 1Score+1
			// bit 3 - .1Score+1

			CTxIn vin = CTxIn(out.tx->GetHash(), out.i);

			int rounds = GetInputDarksendRounds(vin);
			if (rounds >= nDarksendRoundsMax) continue;
			if (rounds < nDarksendRoundsMin) continue;

			if (fFound100000 && fFound10000 && fFound1000 && fFound100 && fFound10 && fFound1 && fFoundDot1) { //if fulfilled
																											   //we can return this for submission
				if (nValueRet >= nValueMin) {
					//random reduce the max amount we'll submit for anonymity
					nValueMax -= (rand() % (nValueMax / 5));
					//on average use 50% of the inputs or less
					int r = (rand() % (int)vCoins.size());
					if ((int)setCoinsRet.size() > r) return true;
				}
				//Denomination criterion has been met, we can take any matching denominations
				if ((nDenom & (1 << 0)) && out.tx->vout[out.i].nValue == ((100000 * COIN) + 100000000)) { fAccepted = true; }
				else if ((nDenom & (1 << 1)) && out.tx->vout[out.i].nValue == ((10000 * COIN) + 10000000)) { fAccepted = true; }
				else if ((nDenom & (1 << 2)) && out.tx->vout[out.i].nValue == ((1000 * COIN) + 1000000)) { fAccepted = true; }
				else if ((nDenom & (1 << 3)) && out.tx->vout[out.i].nValue == ((100 * COIN) + 100000)) { fAccepted = true; }
				else if ((nDenom & (1 << 4)) && out.tx->vout[out.i].nValue == ((10 * COIN) + 10000)) { fAccepted = true; }
				else if ((nDenom & (1 << 5)) && out.tx->vout[out.i].nValue == ((1 * COIN) + 1000)) { fAccepted = true; }
				else if ((nDenom & (1 << 6)) && out.tx->vout[out.i].nValue == ((.1*COIN) + 100)) { fAccepted = true; }
			}
			else {
				//Criterion has not been satisfied, we will only take 1 of each until it is.
				if ((nDenom & (1 << 0)) && out.tx->vout[out.i].nValue == ((100000 * COIN) + 100000000)) { fAccepted = true; fFound100000 = true; }
				else if ((nDenom & (1 << 1)) && out.tx->vout[out.i].nValue == ((10000 * COIN) + 10000000)) { fAccepted = true; fFound10000 = true; }
				else if ((nDenom & (1 << 1)) && out.tx->vout[out.i].nValue == ((1000 * COIN) + 1000000)) { fAccepted = true; fFound1000 = true; }
				else if ((nDenom & (1 << 1)) && out.tx->vout[out.i].nValue == ((100 * COIN) + 100000)) { fAccepted = true; fFound100 = true; }
				else if ((nDenom & (1 << 1)) && out.tx->vout[out.i].nValue == ((10 * COIN) + 10000)) { fAccepted = true; fFound10 = true; }
				else if ((nDenom & (1 << 2)) && out.tx->vout[out.i].nValue == ((1 * COIN) + 1000)) { fAccepted = true; fFound1 = true; }
				else if ((nDenom & (1 << 3)) && out.tx->vout[out.i].nValue == ((.1*COIN) + 100)) { fAccepted = true; fFoundDot1 = true; }
			}
			if (!fAccepted) continue;

			vin.prevPubKey = out.tx->vout[out.i].scriptPubKey; // the inputs PubKey
			nValueRet += out.tx->vout[out.i].nValue;
			setCoinsRet.push_back(vin);
			setCoinsRet2.push_back(out);
		}
	}

	return (nValueRet >= nValueMin && fFound100000 && fFound10000 && fFound1000 && fFound100 && fFound10 && fFound1 && fFoundDot1);
}

bool CWallet::SelectCoinsDark(int64_t nValueMin, int64_t nValueMax, std::vector<CTxIn>& setCoinsRet, int64_t& nValueRet, int nDarksendRoundsMin, int nDarksendRoundsMax) const
{
	CCoinControl *coinControl = NULL;

	setCoinsRet.clear();
	nValueRet = 0;

	vector<COutput> vCoins;
	AvailableCoinsDeno(vCoins, true, coinControl, nDarksendRoundsMin < 0 ? ONLY_NONDENOMINATED_NOTMN : ONLY_DENOMINATED);

	set<pair<const CWalletTx*, unsigned int> > setCoinsRet2;

	//order the array so fees are first, then denominated money, then the rest.
	sort(vCoins.rbegin(), vCoins.rend(), CompareByPriority());

	//the first thing we get is a fee input, then we'll use as many denominated as possible. then the rest
	BOOST_FOREACH(const COutput& out, vCoins)
	{
		//there's no reason to allow inputs less than 1 COIN into DS (other than denominations smaller than that amount)
		if (out.tx->vout[out.i].nValue < 1 * COIN && out.tx->vout[out.i].nValue != (.1*COIN) + 100) continue;
		if (fMasterNode && out.tx->vout[out.i].nValue == 250000 * COIN) continue; //masternode input

		if (nValueRet + out.tx->vout[out.i].nValue <= nValueMax) {
			CTxIn vin = CTxIn(out.tx->GetHash(), out.i);

			int rounds = GetInputDarksendRounds(vin);
			if (rounds >= nDarksendRoundsMax) continue;
			if (rounds < nDarksendRoundsMin) continue;

			vin.prevPubKey = out.tx->vout[out.i].scriptPubKey; // the inputs PubKey
			nValueRet += out.tx->vout[out.i].nValue;
			setCoinsRet.push_back(vin);
			setCoinsRet2.insert(make_pair(out.tx, out.i));
		}
	}

	// if it's more than min, we're good to return
	if (nValueRet >= nValueMin) return true;

	return false;
}

bool CWallet::SelectCoinsCollateral(std::vector<CTxIn>& setCoinsRet, int64_t& nValueRet) const
{
	vector<COutput> vCoins;

	//printf(" selecting coins for collateral\n");
	AvailableCoins(vCoins);

	//printf("found coins %d\n", (int)vCoins.size());

	set<pair<const CWalletTx*, unsigned int> > setCoinsRet2;

	BOOST_FOREACH(const COutput& out, vCoins)
	{
		// collateral inputs will always be a multiple of DARSEND_COLLATERAL, up to five
		if (IsCollateralAmount(out.tx->vout[out.i].nValue))
		{
			CTxIn vin = CTxIn(out.tx->GetHash(), out.i);

			vin.prevPubKey = out.tx->vout[out.i].scriptPubKey; // the inputs PubKey
			nValueRet += out.tx->vout[out.i].nValue;
			setCoinsRet.push_back(vin);
			setCoinsRet2.insert(make_pair(out.tx, out.i));
			return true;
		}
	}

	return false;
}

int CWallet::CountInputsWithAmount(int64_t nInputAmount)
{
	int64_t nTotal = 0;
	{
		LOCK(cs_wallet);
		for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
		{
			const CWalletTx* pcoin = &(*it).second;
			if (pcoin->IsTrusted()) {
				int nDepth = pcoin->GetDepthInMainChain();

				for (unsigned int i = 0; i < pcoin->vout.size(); i++) {
					//isminetype mine = IsMine(pcoin->vout[i]);
					bool mine = IsMine(pcoin->vout[i]);
					//COutput out = COutput(pcoin, i, nDepth, (mine & ISMINE_SPENDABLE) != ISMINE_NO);
					COutput out = COutput(pcoin, i, nDepth, mine);
					CTxIn vin = CTxIn(out.tx->GetHash(), out.i);

					if (out.tx->vout[out.i].nValue != nInputAmount) continue;
					if (!IsDenominatedAmount(pcoin->vout[i].nValue)) continue;
					//if(IsSpent(out.tx->GetHash(), i) || !IsMine(pcoin->vout[i]) || !IsDenominated(vin)) continue;
					if (pcoin->IsSpent(i) || !IsMine(pcoin->vout[i]) || !IsDenominated(vin)) continue;

					nTotal++;
				}
			}
		}
	}

	return nTotal;
}

bool CWallet::HasCollateralInputs() const
{
	vector<COutput> vCoins;
	AvailableCoins(vCoins);

	int nFound = 0;
	BOOST_FOREACH(const COutput& out, vCoins)
		if (IsCollateralAmount(out.tx->vout[out.i].nValue)) nFound++;

	return nFound > 1; // should have more than one just in case
}

bool CWallet::IsCollateralAmount(int64_t nInputAmount) const
{
	return  nInputAmount == (DARKSEND_COLLATERAL * 5) + DARKSEND_FEE ||
		nInputAmount == (DARKSEND_COLLATERAL * 4) + DARKSEND_FEE ||
		nInputAmount == (DARKSEND_COLLATERAL * 3) + DARKSEND_FEE ||
		nInputAmount == (DARKSEND_COLLATERAL * 2) + DARKSEND_FEE ||
		nInputAmount == (DARKSEND_COLLATERAL * 1) + DARKSEND_FEE;
}

bool CWallet::SelectCoinsWithoutDenomination(int64_t nTargetValue, set<pair<const CWalletTx*, unsigned int> >& setCoinsRet, int64_t& nValueRet) const
{
	CCoinControl *coinControl = NULL;

	vector<COutput> vCoins;
	AvailableCoinsDeno(vCoins, true, coinControl, ONLY_NONDENOMINATED);

	BOOST_FOREACH(const COutput& out, vCoins)
	{
		nValueRet += out.tx->vout[out.i].nValue;
		setCoinsRet.insert(make_pair(out.tx, out.i));
	}
	return (nValueRet >= nTargetValue);
}

bool CWallet::CreateCollateralTransaction(CTransaction& txCollateral, std::string strReason)
{
	/*
	To doublespend a collateral transaction, it will require a fee higher than this. So there's
	still a significant cost.
	*/
	int64_t nFeeRet = 0.001*COIN;

	txCollateral.vin.clear();
	txCollateral.vout.clear();

	CReserveKey reservekey(this);
	int64_t nValueIn2 = 0;
	std::vector<CTxIn> vCoinsCollateral;

	if (!SelectCoinsCollateral(vCoinsCollateral, nValueIn2))
	{
		strReason = "Error: Darksend requires a collateral transaction and could not locate an acceptable input!";
		return false;
	}

	// make our change address
	CScript scriptChange;
	CPubKey vchPubKey;
	assert(reservekey.GetReservedKey(vchPubKey)); // should never fail, as we just unlocked
	scriptChange = GetScriptForDestination(vchPubKey.GetID());
	reservekey.KeepKey();

	BOOST_FOREACH(CTxIn v, vCoinsCollateral)
		txCollateral.vin.push_back(v);

	if (nValueIn2 - DARKSEND_COLLATERAL - nFeeRet > 0) {
		//pay collateral charge in fees
		CTxOut vout3 = CTxOut(nValueIn2 - DARKSEND_COLLATERAL, scriptChange);
		txCollateral.vout.push_back(vout3);
	}

	int vinNumber = 0;
	BOOST_FOREACH(CTxIn v, txCollateral.vin) {
		if (!SignSignature(*this, v.prevPubKey, txCollateral, vinNumber, int(SIGHASH_ALL | SIGHASH_ANYONECANPAY))) {
			BOOST_FOREACH(CTxIn v, vCoinsCollateral)
				UnlockCoin(v.prevout);

			strReason = "CDarkSendPool::Sign - Unable to sign collateral transaction! \n";
			return false;
		}
		vinNumber++;
	}

	return true;
}

bool CWallet::ConvertList(std::vector<CTxIn> vCoins, std::vector<int64_t>& vecAmounts)
{
	BOOST_FOREACH(CTxIn i, vCoins) {
		if (mapWallet.count(i.prevout.hash))
		{
			CWalletTx& wtx = mapWallet[i.prevout.hash];
			if (i.prevout.n < wtx.vout.size()) {
				vecAmounts.push_back(wtx.vout[i.prevout.n].nValue);
			}
		}
		else {
			printf("ConvertList -- Couldn't find transaction\n");
		}
	}
	return true;
}

//S
bool CWallet::CreateTransaction(const vector<pair<CScript, int64> >& vecSend,
	CWalletTx& wtxNew, CReserveKey& reservekey, int64& nFeeRet, std::string& strFailReason, const CCoinControl* coinControl)
{
	int64 nValue = 0;
	BOOST_FOREACH(const PAIRTYPE(CScript, int64)& s, vecSend)
	{
		if (nValue < 0)
		{
			strFailReason = _("Transaction amounts must be positive");
			return false;
		}
		nValue += s.second;
	}
	if (vecSend.empty() || nValue < 0)
	{
		strFailReason = _("Transaction amounts must be positive");
		return false;
	}

	wtxNew.BindWallet(this);

	{
		LOCK2(cs_main, cs_wallet);
		{
			nFeeRet = nTransactionFee;
			loop
			{
				wtxNew.vin.clear();
			wtxNew.vout.clear();
			wtxNew.fFromMe = true;

			int64 nTotalValue = nValue + nFeeRet;
			double dPriority = 0;
			// vouts to the payees
			BOOST_FOREACH(const PAIRTYPE(CScript, int64)& s, vecSend)
			{
				CTxOut txout(s.second, s.first);
				if (txout.IsDust())
				{
					strFailReason = _("Transaction amount too small");
					return false;
				}
				wtxNew.vout.push_back(txout);
			}

			// Choose coins to use
			set<pair<const CWalletTx*,unsigned int> > setCoins;
			int64 nValueIn = 0;
			if (!SelectCoins(nTotalValue, setCoins, nValueIn, coinControl))
			{
				strFailReason = _("Insufficient funds");
				return false;
			}
			BOOST_FOREACH(PAIRTYPE(const CWalletTx*, unsigned int) pcoin, setCoins)
			{
				int64 nCredit = pcoin.first->vout[pcoin.second].nValue;
				//The priority after the next block (depth+1) is used instead of the current,
				//reflecting an assumption the user would accept a bit more delay for
				//a chance at a free transaction.
				dPriority += (double)nCredit * (pcoin.first->GetDepthInMainChain() + 1);
			}

			int64 nChange = nValueIn - nValue - nFeeRet;
			// if sub-cent change is required, the fee must be raised to at least nMinTxFee
			// or until nChange becomes zero
			// NOTE: this depends on the exact behaviour of GetMinFee
			if (nFeeRet < CTransaction::nMinTxFee && nChange > 0 && nChange < CENT)
			{
				int64 nMoveToFee = min(nChange, CTransaction::nMinTxFee - nFeeRet);
				nChange -= nMoveToFee;
				nFeeRet += nMoveToFee;
			}

			if (nChange > 0)
			{
				// Fill a vout to ourself
				// TODO: pass in scriptChange instead of reservekey so
				// change transaction isn't always pay-to-bitcoin-address
				CScript scriptChange;

				// coin control: send change to custom address
				if (coinControl && !boost::get<CNoDestination>(&coinControl->destChange))
					scriptChange.SetDestination(coinControl->destChange);

				// no coin control: send change to newly generated address
				else
				{
					// Note: We use a new key here to keep it from being obvious which side is the change.
					//  The drawback is that by not reusing a previous key, the change may be lost if a
					//  backup is restored, if the backup doesn't have the new private key for the change.
					//  If we reused the old key, it would be possible to add code to look for and
					//  rediscover unknown transactions that were written with keys of ours to recover
					//  post-backup change.

					// Reserve a new key pair from key pool
					CPubKey vchPubKey;
					assert(reservekey.GetReservedKey(vchPubKey)); // should never fail, as we just unlocked

					scriptChange.SetDestination(vchPubKey.GetID());
				}

				CTxOut newTxOut(nChange, scriptChange);

				// Never create dust outputs; if we would, just
				// add the dust to the fee.
				if (newTxOut.IsDust())
				{
					nFeeRet += nChange;
					reservekey.ReturnKey();
				}
				else
				{
					// Insert change txn at random position:
					vector<CTxOut>::iterator position = wtxNew.vout.begin() + GetRandInt(wtxNew.vout.size() + 1);
					wtxNew.vout.insert(position, newTxOut);
				}
			}
			else
				reservekey.ReturnKey();

			// Fill vin
			BOOST_FOREACH(const PAIRTYPE(const CWalletTx*,unsigned int)& coin, setCoins)
				wtxNew.vin.push_back(CTxIn(coin.first->GetHash(),coin.second));

			// Sign
			int nIn = 0;
			BOOST_FOREACH(const PAIRTYPE(const CWalletTx*,unsigned int)& coin, setCoins)
				if (!SignSignature(*this, *coin.first, wtxNew, nIn++))
				{
					strFailReason = _("Signing transaction failed");
					return false;
				}

			// Limit size
			unsigned int nBytes = ::GetSerializeSize(*(CTransaction*)&wtxNew, SER_NETWORK, PROTOCOL_VERSION);
			if (nBytes >= MAX_STANDARD_TX_SIZE)
			{
				strFailReason = _("Transaction too large");
				return false;
			}
			dPriority /= nBytes;

			// Check that enough fee is included
			int64 nPayFee = nTransactionFee * (1 + (int64)nBytes / 1000);
			bool fAllowFree = CTransaction::AllowFree(dPriority);
			int64 nMinFee = wtxNew.GetMinFee(1, fAllowFree, GMF_SEND);
			if (nFeeRet < max(nPayFee, nMinFee))
			{
				nFeeRet = max(nPayFee, nMinFee);
				continue;
			}

			// Fill vtxPrev by copying from previous transactions vtxPrev
			wtxNew.AddSupportingTransactions();
			wtxNew.fTimeReceivedIsTxTime = true;

			break;
			}
		}
	}
	return true;
}

bool CWallet::CreateTransaction(CScript scriptPubKey, int64 nValue,
	CWalletTx& wtxNew, CReserveKey& reservekey, int64& nFeeRet, std::string& strFailReason, const CCoinControl* coinControl)
{
	vector< pair<CScript, int64> > vecSend;
	vecSend.push_back(make_pair(scriptPubKey, nValue));
	return CreateTransaction(vecSend, wtxNew, reservekey, nFeeRet, strFailReason, coinControl);
}


//L
bool CWallet::CreateTransaction(const vector<pair<CScript, int64_t> >& vecSend, 
CWalletTx& wtxNew, CReserveKey& reservekey, int64_t& nFeeRet, int32_t& nChangePos, std::string& strFailReason, 
const CCoinControl* coinControl, AvailableCoinsType coin_type, bool useIX)

{
	int64 nValue = 0;
	BOOST_FOREACH(const PAIRTYPE(CScript, int64)& s, vecSend)
	{
		if (nValue < 0)
		{
			strFailReason = _("Transaction amounts must be positive");
			return false;
		}
		nValue += s.second;
	}
	if (vecSend.empty() || nValue < 0)
	{
		strFailReason = _("Transaction amounts must be positive");
		return false;
	}

	wtxNew.BindWallet(this);

	{
		LOCK2(cs_main, cs_wallet);
		{
			nFeeRet = nTransactionFee;
			loop
			{
				wtxNew.vin.clear();
			wtxNew.vout.clear();
			wtxNew.fFromMe = true;

			int64 nTotalValue = nValue + nFeeRet;
			double dPriority = 0;
			// vouts to the payees
			BOOST_FOREACH(const PAIRTYPE(CScript, int64)& s, vecSend)
			{
				CTxOut txout(s.second, s.first);
				if (txout.IsDust())
				{
					strFailReason = _("Transaction amount too small");
					return false;
				}
				wtxNew.vout.push_back(txout);
			}

			// Choose coins to use
			set<pair<const CWalletTx*,unsigned int> > setCoins;
			int64 nValueIn = 0;
			if (!SelectCoins(nTotalValue, setCoins, nValueIn, coinControl))
			{
				strFailReason = _("Insufficient funds");
				return false;
			}
			BOOST_FOREACH(PAIRTYPE(const CWalletTx*, unsigned int) pcoin, setCoins)
			{
				int64 nCredit = pcoin.first->vout[pcoin.second].nValue;
				//The priority after the next block (depth+1) is used instead of the current,
				//reflecting an assumption the user would accept a bit more delay for
				//a chance at a free transaction.
				dPriority += (double)nCredit * (pcoin.first->GetDepthInMainChain() + 1);
			}

			int64 nChange = nValueIn - nValue - nFeeRet;
			// if sub-cent change is required, the fee must be raised to at least nMinTxFee
			// or until nChange becomes zero
			// NOTE: this depends on the exact behaviour of GetMinFee
			if (nFeeRet < CTransaction::nMinTxFee && nChange > 0 && nChange < CENT)
			{
				int64 nMoveToFee = min(nChange, CTransaction::nMinTxFee - nFeeRet);
				nChange -= nMoveToFee;
				nFeeRet += nMoveToFee;
			}

			if (nChange > 0)
			{
				// Fill a vout to ourself
				// TODO: pass in scriptChange instead of reservekey so
				// change transaction isn't always pay-to-bitcoin-address
				CScript scriptChange;

				// coin control: send change to custom address
				if (coinControl && !boost::get<CNoDestination>(&coinControl->destChange))
					scriptChange.SetDestination(coinControl->destChange);

				// no coin control: send change to newly generated address
				else
				{
					// Note: We use a new key here to keep it from being obvious which side is the change.
					//  The drawback is that by not reusing a previous key, the change may be lost if a
					//  backup is restored, if the backup doesn't have the new private key for the change.
					//  If we reused the old key, it would be possible to add code to look for and
					//  rediscover unknown transactions that were written with keys of ours to recover
					//  post-backup change.

					// Reserve a new key pair from key pool
					CPubKey vchPubKey;
					assert(reservekey.GetReservedKey(vchPubKey)); // should never fail, as we just unlocked

					scriptChange.SetDestination(vchPubKey.GetID());
				}

				CTxOut newTxOut(nChange, scriptChange);

				// Never create dust outputs; if we would, just
				// add the dust to the fee.
				if (newTxOut.IsDust())
				{
					nFeeRet += nChange;
					reservekey.ReturnKey();
				}
				else
				{
					// Insert change txn at random position:
					vector<CTxOut>::iterator position = wtxNew.vout.begin() + GetRandInt(wtxNew.vout.size() + 1);
					wtxNew.vout.insert(position, newTxOut);
				}
			}
			else
				reservekey.ReturnKey();

			// Fill vin
			BOOST_FOREACH(const PAIRTYPE(const CWalletTx*,unsigned int)& coin, setCoins)
				wtxNew.vin.push_back(CTxIn(coin.first->GetHash(),coin.second));

			// Sign
			int nIn = 0;
			BOOST_FOREACH(const PAIRTYPE(const CWalletTx*,unsigned int)& coin, setCoins)
				if (!SignSignature(*this, *coin.first, wtxNew, nIn++))
				{
					strFailReason = _("Signing transaction failed");
					return false;
				}

			// Limit size
			unsigned int nBytes = ::GetSerializeSize(*(CTransaction*)&wtxNew, SER_NETWORK, PROTOCOL_VERSION);
			if (nBytes >= MAX_STANDARD_TX_SIZE)
			{
				strFailReason = _("Transaction too large");
				return false;
			}
			dPriority /= nBytes;

			// Check that enough fee is included
			int64 nPayFee = nTransactionFee * (1 + (int64)nBytes / 1000);
			bool fAllowFree = CTransaction::AllowFree(dPriority);
			int64 nMinFee = wtxNew.GetMinFee(1, fAllowFree, GMF_SEND);
			if (nFeeRet < max(nPayFee, nMinFee))
			{
				nFeeRet = max(nPayFee, nMinFee);
				continue;
			}

			// Fill vtxPrev by copying from previous transactions vtxPrev
			wtxNew.AddSupportingTransactions();
			wtxNew.fTimeReceivedIsTxTime = true;

			break;
			}
		}
	}
	return true;
}

bool CWallet::CreateTransaction(CScript scriptPubKey, int64_t nValue, 
	std::string& sNarr, CWalletTx& wtxNew, CReserveKey& reservekey, int64_t& nFeeRet, const CCoinControl* coinControl)
{
	std::string strFailReason;
	return CreateTransaction(scriptPubKey, static_cast<int64>(nValue),
		wtxNew, reservekey, (int64&)(nFeeRet),strFailReason,coinControl);
}


// Call after CreateTransaction unless you want to abort
bool CWallet::CommitTransaction(CWalletTx& wtxNew, CReserveKey& reservekey)
{
    {
        LOCK2(cs_main, cs_wallet);
        printf("CommitTransaction:\n%s", wtxNew.ToString().c_str());
        {
            // This is only to keep the database open to defeat the auto-flush for the
            // duration of this scope.  This is the only place where this optimization
            // maybe makes sense; please don't do it anywhere else.
            CWalletDB* pwalletdb = fFileBacked ? new CWalletDB(strWalletFile,"r") : NULL;

            // Take key pair from key pool so it won't be used again
            reservekey.KeepKey();

            // Add tx to wallet, because if it has change it's also ours,
            // otherwise just for transaction history.
            AddToWallet(wtxNew);

            // Mark old coins as spent
            set<CWalletTx*> setCoins;
            BOOST_FOREACH(const CTxIn& txin, wtxNew.vin)
            {
                CWalletTx &coin = mapWallet[txin.prevout.hash];
                coin.BindWallet(this);
                coin.MarkSpent(txin.prevout.n);
                coin.WriteToDisk();
                NotifyTransactionChanged(this, coin.GetHash(), CT_UPDATED);
            }

            if (fFileBacked)
                delete pwalletdb;
        }

        // Track how many getdata requests our transaction gets
        mapRequestCount[wtxNew.GetHash()] = 0;

        // Broadcast
        if (!wtxNew.AcceptToMemoryPool(true, false))
        {
            // This must not fail. The transaction has already been signed and recorded.
            printf("CommitTransaction() : Error: Transaction not valid");
            return false;
        }
        wtxNew.RelayWalletTransaction();
    }
    return true;
}


string CWallet::SendMoney(CScript scriptPubKey, CAmount nValue, CWalletTx& wtxNew, bool fAskFee)
{
    CReserveKey reservekey(this);
    int64 nFeeRequired;

    if (IsLocked())
    {
        string strError = _("Error: Wallet locked, unable to create transaction!");
        printf("SendMoney() : %s", strError.c_str());
        return strError;
    }
    string strError;
    if (!CreateTransaction(scriptPubKey, nValue, wtxNew, reservekey, nFeeRequired, strError))
    {
        if (nValue + nFeeRequired > GetBalance())
            strError = strprintf(_("Error: This transaction requires a transaction fee of at least %s because of its amount, complexity, or use of recently received funds!"), FormatMoney(nFeeRequired).c_str());
        printf("SendMoney() : %s\n", strError.c_str());
        return strError;
    }

    if (fAskFee && !uiInterface.ThreadSafeAskFee(nFeeRequired))
        return "ABORTED";

    if (!CommitTransaction(wtxNew, reservekey))
        return _("Error: The transaction was rejected! This might happen if some of the coins in your wallet were already spent, such as if you used a copy of wallet.dat and coins were spent in the copy but not marked as spent here.");

    return "";
}

string CWallet::SendMoneyToDestination(const CTxDestination& address, int64 nValue, CWalletTx& wtxNew, bool fAskFee)
{
    // Check amount
    if (nValue <= 0)
        return _("Invalid amount");
    if (nValue + nTransactionFee > GetBalance())
        return _("Insufficient funds");

    // Parse Bitcoin address
    CScript scriptPubKey;
    scriptPubKey.SetDestination(address);

    return SendMoney(scriptPubKey, nValue, wtxNew, fAskFee);
}

string CWallet::PrepareDarksendDenominate(int minRounds, int maxRounds)
{
	if (IsLocked())
		return _("Error: Wallet locked, unable to create transaction!");

	if (darkSendPool.GetState() != POOL_STATUS_ERROR && darkSendPool.GetState() != POOL_STATUS_SUCCESS)
		if (darkSendPool.GetMyTransactionCount() > 0)
			return _("Error: You already have pending entries in the Darksend pool");

	// ** find the coins we'll use
	std::vector<CTxIn> vCoins;
	std::vector<COutput> vCoins2;
	int64_t nValueIn = 0;
	CReserveKey reservekey(this);

	/*
	Select the coins we'll use
	if minRounds >= 0 it means only denominated inputs are going in and coming out
	*/
	if (minRounds >= 0) {
		if (!SelectCoinsByDenominations(darkSendPool.sessionDenom, 0.1*COIN, DARKSEND_POOL_MAX, vCoins, vCoins2, nValueIn, minRounds, maxRounds))
			return _("Insufficient funds");
	}

	// calculate total value out
	int64_t nTotalValue = GetTotalValue(vCoins);
	printf("PrepareDarksendDenominate - preparing darksend denominate . Got: %d \n", nTotalValue);

	//--------------
	BOOST_FOREACH(CTxIn v, vCoins)
		LockCoin(v.prevout);

	// denominate our funds
	int64_t nValueLeft = nTotalValue;
	std::vector<CTxOut> vOut;
	std::vector<int64_t> vDenoms;

	/*
	TODO: Front load with needed denominations (e.g. .1, 1 )
	*/

	/*
	Add all denominations once
	The beginning of the list is front loaded with each possible
	denomination in random order. This means we'll at least get 1
	of each that is required as outputs.
	*/
	BOOST_FOREACH(int64_t d, darkSendDenominations) {
		vDenoms.push_back(d);
		vDenoms.push_back(d);
	}

	//randomize the order of these denominations
	std::random_shuffle(vDenoms.begin(), vDenoms.end());

	/*
	Build a long list of denominations
	Next we'll build a long random list of denominations to add.
	Eventually as the algorithm goes through these it'll find the ones
	it nees to get exact change.
	*/
	for (int i = 0; i <= 500; i++)
		BOOST_FOREACH(int64_t d, darkSendDenominations)
		vDenoms.push_back(d);

	//randomize the order of inputs we get back
	std::random_shuffle(vDenoms.begin() + (int)darkSendDenominations.size() + 1, vDenoms.end());

	// Make outputs by looping through denominations randomly
	BOOST_REVERSE_FOREACH(int64_t v, vDenoms) {
		//only use the ones that are approved
		bool fAccepted = false;
		if ((darkSendPool.sessionDenom & (1 << 0)) && v == ((100000 * COIN) + 100000000)) { fAccepted = true; }
		else if ((darkSendPool.sessionDenom & (1 << 1)) && v == ((10000 * COIN) + 10000000)) { fAccepted = true; }
		else if ((darkSendPool.sessionDenom & (1 << 2)) && v == ((1000 * COIN) + 1000000)) { fAccepted = true; }
		else if ((darkSendPool.sessionDenom & (1 << 3)) && v == ((100 * COIN) + 100000)) { fAccepted = true; }
		else if ((darkSendPool.sessionDenom & (1 << 4)) && v == ((10 * COIN) + 10000)) { fAccepted = true; }
		else if ((darkSendPool.sessionDenom & (1 << 5)) && v == ((1 * COIN) + 1000)) { fAccepted = true; }
		else if ((darkSendPool.sessionDenom & (1 << 6)) && v == ((.1*COIN) + 100)) { fAccepted = true; }
		if (!fAccepted) continue;

		int nOutputs = 0;

		// add each output up to 10 times until it can't be added again
		if (nValueLeft - v >= 0 && nOutputs <= 10) {
			CScript scriptChange;
			CPubKey vchPubKey;
			//use a unique change address
			assert(reservekey.GetReservedKey(vchPubKey)); // should never fail, as we just unlocked
			scriptChange = GetScriptForDestination(vchPubKey.GetID());
			reservekey.KeepKey();

			CTxOut o(v, scriptChange);
			vOut.push_back(o);

			//increment outputs and subtract denomination amount
			nOutputs++;
			nValueLeft -= v;
		}

		if (nValueLeft == 0) break;
	}

	//back up mode , incase we couldn't successfully make the outputs for some reason
	if (vOut.size() > 40 || darkSendPool.GetDenominations(vOut) != darkSendPool.sessionDenom || nValueLeft != 0) {
		vOut.clear();
		nValueLeft = nTotalValue;

		// Make outputs by looping through denominations, from small to large

		BOOST_FOREACH(const COutput& out, vCoins2) {
			CScript scriptChange;
			CPubKey vchPubKey;
			//use a unique change address
			assert(reservekey.GetReservedKey(vchPubKey)); // should never fail, as we just unlocked
			scriptChange = GetScriptForDestination(vchPubKey.GetID());
			reservekey.KeepKey();

			CTxOut o(out.tx->vout[out.i].nValue, scriptChange);
			vOut.push_back(o);

			//increment outputs and subtract denomination amount
			nValueLeft -= out.tx->vout[out.i].nValue;

			if (nValueLeft == 0) break;
		}

	}

	if (darkSendPool.GetDenominations(vOut) != darkSendPool.sessionDenom)
		return "Error: can't make current denominated outputs";

	// we don't support change at all
	if (nValueLeft != 0)
		return "Error: change left-over in pool. Must use denominations only";


	//randomize the output order
	std::random_shuffle(vOut.begin(), vOut.end());

	darkSendPool.SendDarksendDenominate(vCoins, vOut, nValueIn);

	return "";
}


int64_t CWallet::GetTotalValue(std::vector<CTxIn> vCoins) {
	int64_t nTotalValue = 0;
	CWalletTx wtx;
	BOOST_FOREACH(CTxIn i, vCoins) {
		if (mapWallet.count(i.prevout.hash))
		{
			CWalletTx& wtx = mapWallet[i.prevout.hash];
			if (i.prevout.n < wtx.vout.size()) {
				nTotalValue += wtx.vout[i.prevout.n].nValue;
			}
		}
		else {
			printf("GetTotalValue -- Couldn't find transaction\n");
		}
	}
	return nTotalValue;
}

DBErrors CWallet::LoadWallet(bool& fFirstRunRet)
{
    if (!fFileBacked)
        return DB_LOAD_OK;
    fFirstRunRet = false;
    DBErrors nLoadWalletRet = CWalletDB(strWalletFile,"cr+").LoadWallet(this);
    if (nLoadWalletRet == DB_NEED_REWRITE)
    {
        if (CDB::Rewrite(strWalletFile, "\x04pool"))
        {
            setKeyPool.clear();
            // Note: can't top-up keypool here, because wallet is locked.
            // User will be prompted to unlock wallet the next operation
            // the requires a new key.
        }
    }

    if (nLoadWalletRet != DB_LOAD_OK)
        return nLoadWalletRet;
    fFirstRunRet = !vchDefaultKey.IsValid();

    return DB_LOAD_OK;
}


bool CWallet::SetAddressBookName(const CTxDestination& address, const string& strName)
{
    std::map<CTxDestination, std::string>::iterator mi = mapAddressBook.find(address);
    mapAddressBook[address] = strName;
    NotifyAddressBookChanged(this, address, strName, ::IsMine(*this, address), (mi == mapAddressBook.end()) ? CT_NEW : CT_UPDATED);
    if (!fFileBacked)
        return false;
    return CWalletDB(strWalletFile).WriteName(CBitcoinAddress(address).ToString(), strName);
}

bool CWallet::DelAddressBookName(const CTxDestination& address)
{
    mapAddressBook.erase(address);
    NotifyAddressBookChanged(this, address, "", ::IsMine(*this, address), CT_DELETED);
    if (!fFileBacked)
        return false;
    return CWalletDB(strWalletFile).EraseName(CBitcoinAddress(address).ToString());
}


void CWallet::PrintWallet(const CBlock& block)
{
    {
        LOCK(cs_wallet);
        if (mapWallet.count(block.vtx[0].GetHash()))
        {
            CWalletTx& wtx = mapWallet[block.vtx[0].GetHash()];
            printf("    mine:  %d  %d  %"PRI64d"", wtx.GetDepthInMainChain(), wtx.GetBlocksToMaturity(), wtx.GetCredit());
        }
    }
    printf("\n");
}

bool CWallet::GetTransaction(const uint256 &hashTx, CWalletTx& wtx)
{
    {
        LOCK(cs_wallet);
        map<uint256, CWalletTx>::iterator mi = mapWallet.find(hashTx);
        if (mi != mapWallet.end())
        {
            wtx = (*mi).second;
            return true;
        }
    }
    return false;
}

bool CWallet::SetDefaultKey(const CPubKey &vchPubKey)
{
    if (fFileBacked)
    {
        if (!CWalletDB(strWalletFile).WriteDefaultKey(vchPubKey))
            return false;
    }
    vchDefaultKey = vchPubKey;
    return true;
}

bool GetWalletFile(CWallet* pwallet, string &strWalletFileOut)
{
    if (!pwallet->fFileBacked)
        return false;
    strWalletFileOut = pwallet->strWalletFile;
    return true;
}

//
// Mark old keypool keys as used,
// and generate all new keys
//
bool CWallet::NewKeyPool()
{
    {
        LOCK(cs_wallet);
        CWalletDB walletdb(strWalletFile);
        BOOST_FOREACH(int64 nIndex, setKeyPool)
            walletdb.ErasePool(nIndex);
        setKeyPool.clear();

        if (IsLocked())
            return false;

        int64 nKeys = max(GetArg("-keypool", 100), (int64)0);
        for (int i = 0; i < nKeys; i++)
        {
            int64 nIndex = i+1;
            walletdb.WritePool(nIndex, CKeyPool(GenerateNewKey()));
            setKeyPool.insert(nIndex);
        }
        printf("CWallet::NewKeyPool wrote %"PRI64d" new keys\n", nKeys);
    }
    return true;
}

bool CWallet::TopUpKeyPool()
{
    {
        LOCK(cs_wallet);

        if (IsLocked())
            return false;

        CWalletDB walletdb(strWalletFile);

        // Top up key pool
        unsigned int nTargetSize = max(GetArg("-keypool", 100), 0LL);
        while (setKeyPool.size() < (nTargetSize + 1))
        {
            int64 nEnd = 1;
            if (!setKeyPool.empty())
                nEnd = *(--setKeyPool.end()) + 1;
            if (!walletdb.WritePool(nEnd, CKeyPool(GenerateNewKey())))
                throw runtime_error("TopUpKeyPool() : writing generated key failed");
            setKeyPool.insert(nEnd);
            printf("keypool added key %"PRI64d", size=%"PRIszu"\n", nEnd, setKeyPool.size());
        }
    }
    return true;
}

void CWallet::ReserveKeyFromKeyPool(int64& nIndex, CKeyPool& keypool)
{
    nIndex = -1;
    keypool.vchPubKey = CPubKey();
    {
        LOCK(cs_wallet);

        if (!IsLocked())
            TopUpKeyPool();

        // Get the oldest key
        if(setKeyPool.empty())
            return;

        CWalletDB walletdb(strWalletFile);

        nIndex = *(setKeyPool.begin());
        setKeyPool.erase(setKeyPool.begin());
        if (!walletdb.ReadPool(nIndex, keypool))
            throw runtime_error("ReserveKeyFromKeyPool() : read failed");
        if (!HaveKey(keypool.vchPubKey.GetID()))
            throw runtime_error("ReserveKeyFromKeyPool() : unknown key in key pool");
        assert(keypool.vchPubKey.IsValid());
        printf("keypool reserve %"PRI64d"\n", nIndex);
    }
}

int64 CWallet::AddReserveKey(const CKeyPool& keypool)
{
    {
        LOCK2(cs_main, cs_wallet);
        CWalletDB walletdb(strWalletFile);

        int64 nIndex = 1 + *(--setKeyPool.end());
        if (!walletdb.WritePool(nIndex, keypool))
            throw runtime_error("AddReserveKey() : writing added key failed");
        setKeyPool.insert(nIndex);
        return nIndex;
    }
    return -1;
}

void CWallet::KeepKey(int64 nIndex)
{
    // Remove from key pool
    if (fFileBacked)
    {
        CWalletDB walletdb(strWalletFile);
        walletdb.ErasePool(nIndex);
    }
    printf("keypool keep %"PRI64d"\n", nIndex);
}

void CWallet::ReturnKey(int64 nIndex)
{
    // Return to key pool
    {
        LOCK(cs_wallet);
        setKeyPool.insert(nIndex);
    }
    printf("keypool return %"PRI64d"\n", nIndex);
}

bool CWallet::GetKeyFromPool(CPubKey& result, bool fAllowReuse)
{
    int64 nIndex = 0;
    CKeyPool keypool;
    {
        LOCK(cs_wallet);
        ReserveKeyFromKeyPool(nIndex, keypool);
        if (nIndex == -1)
        {
            if (fAllowReuse && vchDefaultKey.IsValid())
            {
                result = vchDefaultKey;
                return true;
            }
            if (IsLocked()) return false;
            result = GenerateNewKey();
            return true;
        }
        KeepKey(nIndex);
        result = keypool.vchPubKey;
    }
    return true;
}

int64 CWallet::GetOldestKeyPoolTime()
{
    int64 nIndex = 0;
    CKeyPool keypool;
    ReserveKeyFromKeyPool(nIndex, keypool);
    if (nIndex == -1)
        return GetTime();
    ReturnKey(nIndex);
    return keypool.nTime;
}

std::map<CTxDestination, int64> CWallet::GetAddressBalances()
{
    map<CTxDestination, int64> balances;

    {
        LOCK(cs_wallet);
        BOOST_FOREACH(PAIRTYPE(uint256, CWalletTx) walletEntry, mapWallet)
        {
            CWalletTx *pcoin = &walletEntry.second;

            if (!pcoin->IsFinal() || !pcoin->IsConfirmed())
                continue;

            if (pcoin->IsCoinBase() && pcoin->GetBlocksToMaturity() > 0)
                continue;

            int nDepth = pcoin->GetDepthInMainChain();
            if (nDepth < (pcoin->IsFromMe() ? 0 : 1))
                continue;

            for (unsigned int i = 0; i < pcoin->vout.size(); i++)
            {
                CTxDestination addr;
                if (!IsMine(pcoin->vout[i]))
                    continue;
                if(!ExtractDestination(pcoin->vout[i].scriptPubKey, addr))
                    continue;

                int64 n = pcoin->IsSpent(i) ? 0 : pcoin->vout[i].nValue;

                if (!balances.count(addr))
                    balances[addr] = 0;
                balances[addr] += n;
            }
        }
    }

    return balances;
}

set< set<CTxDestination> > CWallet::GetAddressGroupings()
{
    set< set<CTxDestination> > groupings;
    set<CTxDestination> grouping;

    BOOST_FOREACH(PAIRTYPE(uint256, CWalletTx) walletEntry, mapWallet)
    {
        CWalletTx *pcoin = &walletEntry.second;

        if (pcoin->vin.size() > 0)
        {
            bool any_mine = false;
            // group all input addresses with each other
            BOOST_FOREACH(CTxIn txin, pcoin->vin)
            {
                CTxDestination address;
                if(!IsMine(txin)) /* If this input isn't mine, ignore it */
                    continue;
                if(!ExtractDestination(mapWallet[txin.prevout.hash].vout[txin.prevout.n].scriptPubKey, address))
                    continue;
                grouping.insert(address);
                any_mine = true;
            }

            // group change with input addresses
            if (any_mine)
            {
               BOOST_FOREACH(CTxOut txout, pcoin->vout)
                   if (IsChange(txout))
                   {
                       CTxDestination txoutAddr;
                       if(!ExtractDestination(txout.scriptPubKey, txoutAddr))
                           continue;
                       grouping.insert(txoutAddr);
                   }
            }
            if (grouping.size() > 0)
            {
                groupings.insert(grouping);
                grouping.clear();
            }
        }

        // group lone addrs by themselves
        for (unsigned int i = 0; i < pcoin->vout.size(); i++)
            if (IsMine(pcoin->vout[i]))
            {
                CTxDestination address;
                if(!ExtractDestination(pcoin->vout[i].scriptPubKey, address))
                    continue;
                grouping.insert(address);
                groupings.insert(grouping);
                grouping.clear();
            }
    }

    set< set<CTxDestination>* > uniqueGroupings; // a set of pointers to groups of addresses
    map< CTxDestination, set<CTxDestination>* > setmap;  // map addresses to the unique group containing it
    BOOST_FOREACH(set<CTxDestination> grouping, groupings)
    {
        // make a set of all the groups hit by this new group
        set< set<CTxDestination>* > hits;
        map< CTxDestination, set<CTxDestination>* >::iterator it;
        BOOST_FOREACH(CTxDestination address, grouping)
            if ((it = setmap.find(address)) != setmap.end())
                hits.insert((*it).second);

        // merge all hit groups into a new single group and delete old groups
        set<CTxDestination>* merged = new set<CTxDestination>(grouping);
        BOOST_FOREACH(set<CTxDestination>* hit, hits)
        {
            merged->insert(hit->begin(), hit->end());
            uniqueGroupings.erase(hit);
            delete hit;
        }
        uniqueGroupings.insert(merged);

        // update setmap
        BOOST_FOREACH(CTxDestination element, *merged)
            setmap[element] = merged;
    }

    set< set<CTxDestination> > ret;
    BOOST_FOREACH(set<CTxDestination>* uniqueGrouping, uniqueGroupings)
    {
        ret.insert(*uniqueGrouping);
        delete uniqueGrouping;
    }

    return ret;
}

bool CReserveKey::GetReservedKey(CPubKey& pubkey)
{
    if (nIndex == -1)
    {
        CKeyPool keypool;
        pwallet->ReserveKeyFromKeyPool(nIndex, keypool);
        if (nIndex != -1)
            vchPubKey = keypool.vchPubKey;
        else {
            if (pwallet->vchDefaultKey.IsValid()) {
                printf("CReserveKey::GetReservedKey(): Warning: Using default key instead of a new key, top up your keypool!");
                vchPubKey = pwallet->vchDefaultKey;
            } else
                return false;
        }
    }
    assert(vchPubKey.IsValid());
    pubkey = vchPubKey;
    return true;
}

void CReserveKey::KeepKey()
{
    if (nIndex != -1)
        pwallet->KeepKey(nIndex);
    nIndex = -1;
    vchPubKey = CPubKey();
}

void CReserveKey::ReturnKey()
{
    if (nIndex != -1)
        pwallet->ReturnKey(nIndex);
    nIndex = -1;
    vchPubKey = CPubKey();
}

void CWallet::GetAllReserveKeys(set<CKeyID>& setAddress)
{
    setAddress.clear();

    CWalletDB walletdb(strWalletFile);

    LOCK2(cs_main, cs_wallet);
    BOOST_FOREACH(const int64& id, setKeyPool)
    {
        CKeyPool keypool;
        if (!walletdb.ReadPool(id, keypool))
            throw runtime_error("GetAllReserveKeyHashes() : read failed");
        assert(keypool.vchPubKey.IsValid());
        CKeyID keyID = keypool.vchPubKey.GetID();
        if (!HaveKey(keyID))
            throw runtime_error("GetAllReserveKeyHashes() : unknown key in key pool");
        setAddress.insert(keyID);
    }
}

void CWallet::UpdatedTransaction(const uint256 &hashTx)
{
    {
        LOCK(cs_wallet);
        // Only notify UI if this transaction is in this wallet
        map<uint256, CWalletTx>::const_iterator mi = mapWallet.find(hashTx);
        if (mi != mapWallet.end())
            NotifyTransactionChanged(this, hashTx, CT_UPDATED);
    }
}

void CWallet::LockCoin(COutPoint& output)
{
    setLockedCoins.insert(output);
}

void CWallet::UnlockCoin(COutPoint& output)
{
    setLockedCoins.erase(output);
}

void CWallet::UnlockAllCoins()
{
    setLockedCoins.clear();
}

bool CWallet::IsLockedCoin(uint256 hash, unsigned int n) const
{
    COutPoint outpt(hash, n);

    return (setLockedCoins.count(outpt) > 0);
}

void CWallet::ListLockedCoins(std::vector<COutPoint>& vOutpts)
{
    for (std::set<COutPoint>::iterator it = setLockedCoins.begin();
         it != setLockedCoins.end(); it++) {
        COutPoint outpt = (*it);
        vOutpts.push_back(outpt);
    }
}

