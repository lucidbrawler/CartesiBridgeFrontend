// src/components/SubWallet.jsx
import { useState } from 'react';
import { gql, GraphQLClient } from 'graphql-request';
import { ethers } from 'ethers';
import { Toaster, toast } from 'react-hot-toast';

const GRAPHQL_URL = 'http://localhost:8080/graphql'; // Update to your Cartesi GraphQL endpoint

function SubWallet({
  mainWallet,
  mainMnemonic,
  selectedNode,
  fetchBalanceAndNonce,
  sendTransaction,
  send, // Cartesi send for inputs (e.g., lock/unlock)
  address, // L1 address
  loading,
  setLoading,
  subWallets,
  setSubWallets,
  subIndex,
  setSubIndex,
  getWartTxProof
}) {
  const [subError, setSubError] = useState(null);
  const [subSalt, setSubSalt] = useState(null);
  const [regenIndex, setRegenIndex] = useState('');
  const client = new GraphQLClient(GRAPHQL_URL);

  // Per-sub states (using object with sub.index as key)
  const [subDeposits, setSubDeposits] = useState({});
  const [subTxHashes, setSubTxHashes] = useState({});
  const [subVoucherPayloads, setSubVoucherPayloads] = useState({});
  const [subSendTos, setSubSendTos] = useState({});
  const [subSendAmounts, setSubSendAmounts] = useState({});
  const [subSendFees, setSubSendFees] = useState({});
  const [subLockConditions, setSubLockConditions] = useState({});
  const [subUnlockConditions, setSubUnlockConditions] = useState({});
  const [isDepositing, setIsDepositing] = useState({});

  const fetchCartesiSalt = async (userMainAddress) => {
    try {
      const query = gql`{ notices(last: 1) { edges { node { payload } } } }`;
      const data = await client.request(query);
      const noticePayload = data.notices.edges[0]?.node.payload || 'fallback_genesis_hash';
      const timestamp = Math.floor(Date.now() / 1000);
      const composite = ethers.utils.keccak256(ethers.utils.toUtf8Bytes(noticePayload + userMainAddress + timestamp.toString()));
      setSubSalt(composite);
      return composite;
    } catch (err) {
      setSubError('Failed to fetch Cartesi salt');
      return 'fallback_salt';
    }
  };

  const generateLockedSubWallet = async (index) => {
    if (!mainMnemonic) {
      setSubError('Main wallet mnemonic required for derivation');
      toast.error('Main wallet mnemonic required for derivation');
      return;
    }
    const salt = await fetchCartesiSalt(mainWallet.address);
    const saltedIndex = index + parseInt(salt.slice(2, 10), 16) % (2**31 - 1);
    const path = `m/44'/2070'/0'/0/${saltedIndex}'`;
    try {
      const hdNode = ethers.utils.HDNode.fromMnemonic(mainMnemonic).derivePath(path);
      const publicKey = hdNode.publicKey.slice(2);
      const sha = ethers.utils.sha256('0x' + publicKey).slice(2);
      const ripemd = ethers.utils.ripemd160('0x' + sha).slice(2);
      const checksum = ethers.utils.sha256('0x' + ripemd).slice(2, 10);
      const subAddress = ripemd + checksum;
      const newSub = { index: saltedIndex, address: subAddress, locked: false, voucher: null, balance: '0' };
      setSubWallets([...subWallets, newSub]);
      setSubIndex(index + 1);
      toast.success('Sub-wallet generated!');
      await refreshSubBalance(subAddress);
    } catch (err) {
      setSubError('Failed to generate sub-wallet');
      toast.error('Failed to generate sub-wallet');
    }
  };

  const regenerateSubWallet = async (saltedIndex) => {
    if (!mainMnemonic) {
      setSubError('Main mnemonic required');
      return;
    }
    const path = `m/44'/2070'/0'/0/${saltedIndex}'`;
    try {
      const hdNode = ethers.utils.HDNode.fromMnemonic(mainMnemonic).derivePath(path);
      const publicKey = hdNode.publicKey.slice(2);
      const sha = ethers.utils.sha256('0x' + publicKey).slice(2);
      const ripemd = ethers.utils.ripemd160('0x' + sha).slice(2);
      const checksum = ethers.utils.sha256('0x' + ripemd).slice(2, 10);
      const subAddress = ripemd + checksum;
      const regeneratedSub = { index: saltedIndex, address: subAddress, locked: false, voucher: null, balance: '0' };
      setSubWallets(prev => [...prev.filter(sub => sub.index !== saltedIndex), regeneratedSub]);
      toast.success('Sub-wallet regenerated!');
      await refreshSubBalance(subAddress);
    } catch (err) {
      setSubError('Failed to regenerate sub-wallet');
      toast.error('Failed to regenerate sub-wallet');
    }
  };

  const depositToSub = async (sub) => {
  const amount = subDeposits[sub.index] || '';
  if (!amount) return setSubError('Enter deposit amount');
  setIsDepositing(prev => ({ ...prev, [sub.index]: true }));
  setLoading(true);

  const depositToast = toast.loading('Awaiting MetaMask confirmation for deposit...');

  try {
    const data = await sendTransaction(mainWallet.privateKey, mainWallet.address, sub.address, amount, '0.01');
    const txHash = data?.data?.txHash || data?.txHash || data?.hash;
    if (!txHash) throw new Error('No txHash in send response');

    toast.success('Deposited to sub-wallet! Fetching proof and submitting lock...', { id: depositToast });

    // Update balance locally immediately (this is fine, as it's after TX confirm but before lock)
    const updatedSubs = subWallets.map(s => s.index === sub.index ? { ...s, balance: (parseFloat(s.balance) + parseFloat(amount)).toString() } : s);
    setSubWallets(updatedSubs);
    setSubDeposits(prev => ({ ...prev, [sub.index]: '' }));
    setSubTxHashes(prev => ({ ...prev, [sub.index]: txHash }));

    // Submit lock with proof + poll for confirmation (this will update locked state)
    await lockSubWithProof(sub, txHash);

    // Now refresh balance/lock state (will confirm the new locked: true from Cartesi notices)
    await refreshSubBalance(sub.address);

    toast.success('Deposit and lock complete!', { id: depositToast });
  } catch (err) {
    console.error('Deposit or auto-lock failed:', err);
    setSubError('Deposit or auto-lock failed: ' + err.message);
    toast.error('Deposit or auto-lock failed: ' + err.message, { id: depositToast });
  } finally {
    setIsDepositing(prev => ({ ...prev, [sub.index]: false }));
    setLoading(false);
  }
};
  // NEW: Poll for lock notice confirmation
  const pollForLockNotice = async (subAddress, timeoutMs = 30000) => {
    const startTime = Date.now();
    while (Date.now() - startTime < timeoutMs) {
      try {
        const query = gql`
          {
            notices(last: 5) {
              edges {
                node {
                  payload
                }
              }
            }
          }
        `;
        const data = await client.request(query);
        const notices = data.notices.edges.map(edge => {
          try {
            return JSON.parse(ethers.utils.toUtf8String(edge.node.payload));
          } catch {
            return null;
          }
        }).filter(Boolean);

        const lockNotice = notices.find(notice => 
          notice.type === 'subwallet_locked' && 
          notice.subAddress === subAddress && 
          notice.verified === true
        );

        if (lockNotice) {
          return true; // Locked
        }
      } catch (err) {
        console.error('Notice poll error:', err);
      }
      await new Promise(resolve => setTimeout(resolve, 2000)); // Poll every 2s
    }
    return false; // Timeout
  };

  // NEW: Poll for unlock notice confirmation
  const pollForUnlockNotice = async (subAddress, timeoutMs = 30000) => {
    const startTime = Date.now();
    while (Date.now() - startTime < timeoutMs) {
      try {
        const query = gql`
          {
            notices(last: 5) {  # Fetch last 5 to catch recent ones
              edges {
                node {
                  payload
                }
              }
            }
          }
        `;
        const data = await client.request(query);
        const notices = data.notices.edges.map(edge => {
          try {
            return JSON.parse(ethers.utils.toUtf8String(edge.node.payload));  // Decode hex payload if needed
          } catch {
            return null;
          }
        }).filter(Boolean);

        const unlockNotice = notices.find(notice => 
          notice.type === 'subwallet_unlocked' && 
          notice.subAddress === subAddress && 
          notice.verified === true
        );

        if (unlockNotice) {
          return true;  // Unlocked
        }
      } catch (err) {
        console.error('Notice poll error:', err);
      }
      await new Promise(resolve => setTimeout(resolve, 2000));  // Poll every 2s
    }
    return false;  // Timeout, not unlocked
  };

  // NEW: Get current lock state from latest notices (for sync on refresh)
  const isSubLocked = async (subAddress) => {
    try {
      const query = gql`
        {
          notices(last: 20) {  # Fetch more to ensure we catch history
            edges {
              node {
                payload
              }
            }
          }
        }
      `;
      const data = await client.request(query);
      const notices = data.notices.edges.map(edge => {
        try {
          return JSON.parse(ethers.utils.toUtf8String(edge.node.payload));
        } catch {
          return null;
        }
      }).filter(Boolean);

      const relevantNotices = notices.filter(notice => 
        notice.subAddress === subAddress && 
        notice.verified === true && 
        (notice.type === 'subwallet_locked' || notice.type === 'subwallet_unlocked')
      );

      if (relevantNotices.length === 0) {
        return false; // Default not locked if no history
      }

      // Assume edges are ordered newest first (last:20 means recent at index 0)
      const latestNotice = relevantNotices[0];
      return latestNotice.type === 'subwallet_locked';
    } catch (err) {
      console.error('Lock state query error:', err);
      return false; // Default on error
    }
  };

  const lockSubWithProof = async (sub, txHashOverride) => {
    const txHash = txHashOverride || subTxHashes[sub.index] || '';
    const condition = subLockConditions[sub.index] || 'true';
    if (!txHash) return setSubError('Enter tx hash for lock proof');
    setLoading(true);
    try {
      // Optional delay for TX mining
      await new Promise(resolve => setTimeout(resolve, 5000));
      const proof = await getWartTxProof(txHash);
      const payload = { type: 'sub_lock', subAddress: sub.address, proof, recipient: address, condition }; // Added condition for merged handler
      await send(payload); // Use Cartesi send for input
      toast.success('Lock proof submitted! Polling for confirmation...');

      const isLocked = await pollForLockNotice(sub.address);
      if (isLocked) {
        setSubWallets(prev => prev.map(s => s.index === sub.index ? { ...s, locked: true } : s));
        toast.success('Lock confirmed via notice! Sub-wallet locked.');
      } else {
        toast.error('Lock not confirmed within timeout. Check backend logs.');
      }
      setSubTxHashes(prev => ({ ...prev, [sub.index]: '' }));
      setSubLockConditions(prev => ({ ...prev, [sub.index]: '' }));
    } catch (err) {
      console.error('Lock failed:', err);
      setSubError('Lock failed');
      toast.error('Lock failed');
    } finally {
      setLoading(false);
    }
  };

  const requestUnlock = async (sub) => {
    setLoading(true);
    try {
      await send({ type: 'sub_unlock', subAddress: sub.address });
      toast.success('Unlock requested! Polling for confirmation...');

      const isUnlocked = await pollForUnlockNotice(sub.address);
      if (isUnlocked) {
        setSubWallets(prev => prev.map(s => s.index === sub.index ? { ...s, locked: false } : s));
        toast.success('Unlock confirmed via notice! Sub-wallet unlocked.');
      } else {
        toast.error('Unlock not confirmed within timeout. Check backend logs.');
      }
    } catch (err) {
      setSubError('Unlock request failed');
      toast.error('Unlock request failed');
    } finally {
      setLoading(false);
    }
  };

  const handleLock = async (sub) => {
    const condition = subLockConditions[sub.index] || 'true';
    setLoading(true);
    try {
      await send({ type: 'sub_lock', subAddress: sub.address, condition }); // Unified to 'sub_lock'
      toast.success('Sub-wallet lock submitted to Cartesi! Polling for confirmation...');

      const isLocked = await pollForLockNotice(sub.address);
      if (isLocked) {
        setSubWallets(prev => prev.map(s => s.index === sub.index ? { ...s, locked: true } : s));
        toast.success('Lock confirmed via notice!');
      } else {
        toast.error('Lock not confirmed within timeout. Check backend logs.');
      }
    } catch (err) {
      setSubError('Lock submission failed: ' + err.message);
      toast.error('Lock submission failed: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleUnlock = async (sub) => {
    const condition = subUnlockConditions[sub.index] || 'true';
    setLoading(true);
    try {
      await send({ type: 'sub_unlock', subAddress: sub.address, condition }); // Unified to 'sub_unlock'
      toast.success('Sub-wallet unlock submitted to Cartesi! Polling for confirmation...');

      const isUnlocked = await pollForUnlockNotice(sub.address);
      if (isUnlocked) {
        setSubWallets(prev => prev.map(s => s.index === sub.index ? { ...s, locked: false } : s));
        toast.success('Unlock confirmed via notice!');
      } else {
        toast.error('Unlock not confirmed within timeout. Check backend logs.');
      }
    } catch (err) {
      setSubError('Unlock submission failed: ' + err.message);
      toast.error('Unlock submission failed: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  const unlockSubWithVoucher = (sub) => {
    const voucherPayload = subVoucherPayloads[sub.index] || '';
    if (!voucherPayload) return setSubError('Enter voucher payload');
    try {
      if (!voucherPayload.toLowerCase().includes(sub.address.slice(2).toLowerCase())) {
        throw new Error('Voucher payload does not match sub-wallet');
      }
      const updatedSubs = subWallets.map(s => s.index === sub.index ? { ...s, locked: false, voucher: voucherPayload } : s);
      setSubWallets(updatedSubs);
      toast.success('Sub-wallet unlocked!');
      setSubVoucherPayloads(prev => ({ ...prev, [sub.index]: '' }));
    } catch (err) {
      setSubError('Unlock failed: ' + err.message);
      toast.error('Unlock failed: ' + err.message);
    }
  };

  const refreshSubBalance = async (subAddress) => {
    try {
      const { balance: balanceInWart } = await fetchBalanceAndNonce(subAddress, true);
      const locked = await isSubLocked(subAddress); // NEW: Sync lock state from notices
      setSubWallets(prev => prev.map(sub => sub.address === subAddress ? { ...sub, balance: balanceInWart, locked } : sub));
      toast.success('Sub-wallet balance and lock state refreshed!');
    } catch (err) {
      setSubError('Failed to refresh sub balance');
      toast.error('Failed to refresh sub balance');
    }
  };

  const handleSendFromSub = async (sub) => {
    const amount = subSendAmounts[sub.index] || '';
    const fee = subSendFees[sub.index] || '0.01';
    const to = subSendTos[sub.index] || address;
    if (!amount || !fee) {
      setSubError('Enter amount and fee');
      return;
    }
    if (!mainMnemonic) {
      setSubError('Main mnemonic required');
      toast.error('Main mnemonic required');
      return;
    }
    setLoading(true);
    try {
      const path = `m/44'/2070'/0'/0/${sub.index}'`;
      const hdNode = ethers.utils.HDNode.fromMnemonic(mainMnemonic).derivePath(path);
      const subPrivKey = hdNode.privateKey.slice(2);
      await sendTransaction(subPrivKey, sub.address, to, amount, fee);
      toast.success('Sent from sub-wallet!');
      const updatedSubs = subWallets.map(s => s.index === sub.index ? { ...s, balance: (parseFloat(s.balance) - parseFloat(amount)).toString() } : s);
      setSubWallets(updatedSubs);
      setSubSendAmounts(prev => ({ ...prev, [sub.index]: '' }));
      setSubSendFees(prev => ({ ...prev, [sub.index]: '0.01' }));
      // Removed: await refreshSubBalance(sub.address); // Avoid refreshing lock state after send to prevent incorrect locking
      if (to === address) {
        await fetchBalanceAndNonce(address);
      }
    } catch (err) {
      setSubError('Send from sub failed');
      toast.error('Send from sub failed');
    } finally {
      setLoading(false);
    }
  };

  const clearSubWallets = () => {
    setSubWallets([]);
    setSubIndex(0);
    localStorage.removeItem('warthogSubWallets');
    toast.success('Sub-wallets cleared from cache!');
  };

  return (
    <section>
      <h3>Sub-Wallets (Locked with Cartesi Proofs)</h3>
      <button onClick={() => generateLockedSubWallet(subIndex)}>Generate New Sub-Wallet</button>
      <input type="number" placeholder="Enter salted index to regenerate" value={regenIndex} onChange={(e) => setRegenIndex(e.target.value)} />
      <button onClick={() => regenerateSubWallet(Number(regenIndex))}>Regenerate Sub-Wallet</button>
      <button onClick={clearSubWallets} className="danger">Clear All Sub-Wallets</button>
      <ul>
        {subWallets.map(sub => (
          <li key={sub.index}>
            Index: {sub.index} | Address: {sub.address} | Balance: {sub.balance ?? '0'} WART | Locked: {sub.locked ? 'Yes' : 'No'}
            <button onClick={() => refreshSubBalance(sub.address)}>Refresh Balance</button>
            <div>
              <h4>Actions for this Sub-Wallet</h4>
              <input
                type="number"
                placeholder="Deposit Amount"
                value={subDeposits[sub.index] || ''}
                onChange={(e) => setSubDeposits(prev => ({ ...prev, [sub.index]: e.target.value }))}
                disabled={sub.locked || loading}
              />
              <button onClick={() => depositToSub(sub)} disabled={sub.locked || loading || isDepositing[sub.index]}>{isDepositing[sub.index] ? 'Depositing...' : 'Deposit from Main & Auto-Lock'}</button>
              <input
                type="text"
                placeholder="Deposit Tx Hash for Lock"
                value={subTxHashes[sub.index] || ''}
                onChange={(e) => setSubTxHashes(prev => ({ ...prev, [sub.index]: e.target.value }))}
                disabled={sub.locked || loading}
              />
              <button onClick={() => lockSubWithProof(sub)} disabled={sub.locked || loading}>Lock with Proof</button>
              <input
                type="text"
                placeholder="Lock Condition (true/false)"
                value={subLockConditions[sub.index] || 'true'}
                onChange={(e) => setSubLockConditions(prev => ({ ...prev, [sub.index]: e.target.value }))}
                disabled={sub.locked || loading}
              />
              <button onClick={() => handleLock(sub)} disabled={sub.locked || loading}>Test Lock</button>
              {sub.locked && (
                <>
                  <button onClick={() => requestUnlock(sub)} disabled={loading}>Request Unlock</button>
                  <input
                    type="text"
                    placeholder="Unlock Condition (true/false)"
                    value={subUnlockConditions[sub.index] || 'true'}
                    onChange={(e) => setSubUnlockConditions(prev => ({ ...prev, [sub.index]: e.target.value }))}
                    disabled={loading}
                  />
                  <button onClick={() => handleUnlock(sub)} disabled={loading}>Test Unlock</button>
                  <input
                    type="text"
                    placeholder="Voucher Payload to Unlock"
                    value={subVoucherPayloads[sub.index] || ''}
                    onChange={(e) => setSubVoucherPayloads(prev => ({ ...prev, [sub.index]: e.target.value }))}
                    disabled={loading}
                  />
                  <button onClick={() => unlockSubWithVoucher(sub)} disabled={loading}>Unlock with Voucher</button>
                </>
              )}
              <input
                type="text"
                placeholder="To Address (default: main)"
                value={subSendTos[sub.index] || address}
                onChange={(e) => setSubSendTos(prev => ({ ...prev, [sub.index]: e.target.value }))}
                disabled={sub.locked || loading}
              />
              <input
                type="number"
                placeholder="Amount to Send"
                value={subSendAmounts[sub.index] || ''}
                onChange={(e) => setSubSendAmounts(prev => ({ ...prev, [sub.index]: e.target.value }))}
                disabled={sub.locked || loading}
              />
              <input
                type="number"
                placeholder="Fee (e.g., 0.01)"
                value={subSendFees[sub.index] || '0.01'}
                onChange={(e) => setSubSendFees(prev => ({ ...prev, [sub.index]: e.target.value }))}
                disabled={sub.locked || loading}
              />
              <button onClick={() => handleSendFromSub(sub)} disabled={sub.locked || loading}>Send from Sub</button>
            </div>
          </li>
        ))}
      </ul>
      {subError && <div className="error">{subError}</div>}
      <Toaster />
    </section>
  );
}

export default SubWallet;
