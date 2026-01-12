// src/components/SubWallet.jsx
import { useState, useEffect } from 'react';
import { gql, GraphQLClient } from 'graphql-request';
import { ethers } from 'ethers';
import { Toaster, toast } from 'react-hot-toast';
import '../styles/subWallet.css';
const GRAPHQL_URL = 'http://localhost:8080/graphql';

function SubWallet({
  mainWallet,
  mainMnemonic,
  fetchBalanceAndNonce,
  sendTransaction,
  send,
  address, // Warthog main address
  l1Address, // NEW: L1 MetaMask address
  loading,
  setLoading,
  subWallets,
  setSubWallets,
  subIndex,
  setSubIndex,
  getWartTxProof,
}) {
  const [subError, setSubError] = useState(null);
  const [subDeposits, setSubDeposits] = useState({});
  const [subTxHashes, setSubTxHashes] = useState({});
  const [isDepositing, setIsDepositing] = useState({});
  const [autoLockPhase, setAutoLockPhase] = useState({});
const [isUnlocking, setIsUnlocking] = useState({});
  // Withdraw states
  const [subWithdrawAmounts, setSubWithdrawAmounts] = useState({});
  const [subWithdrawFees, setSubWithdrawFees] = useState({});
  const [isWithdrawing, setIsWithdrawing] = useState({});

  // Regenerate state
  const [regenIndex, setRegenIndex] = useState('');

  const client = new GraphQLClient(GRAPHQL_URL);

  // Animated dots
  const LoadingDots = () => {
    const [dots, setDots] = useState(1);
    useEffect(() => {
      const interval = setInterval(() => setDots((prev) => (prev % 3) + 1), 500);
      return () => clearInterval(interval);
    }, []);
    return <span>{'.'.repeat(dots)}</span>;
  };

  const fetchCartesiSalt = async (userMainAddress) => {
    try {
      const { notices } = await client.request(gql`{ notices(last: 1) { edges { node { payload } } } }`);
      const noticePayload = notices.edges[0]?.node.payload || 'fallback';
      const timestamp = Math.floor(Date.now() / 1000);
      return ethers.utils.keccak256(
        ethers.utils.toUtf8Bytes(noticePayload + userMainAddress + timestamp)
      );
    } catch {
      return 'fallback_salt';
    }
  };

  const generateLockedSubWallet = async () => {
    if (!mainMnemonic) return toast.error('Main wallet mnemonic required');

    const salt = await fetchCartesiSalt(mainWallet.address);
    const saltedIndex = subIndex + parseInt(salt.slice(2, 10), 16) % (2 ** 31 - 1);
    const path = `m/44'/2070'/0'/0/${saltedIndex}'`;

    try {
      const hdNode = ethers.utils.HDNode.fromMnemonic(mainMnemonic).derivePath(path);
      const publicKey = hdNode.publicKey.slice(2);
      const sha = ethers.utils.sha256('0x' + publicKey).slice(2);
      const ripemd = ethers.utils.ripemd160('0x' + sha).slice(2);
      const checksum = ethers.utils.sha256('0x' + ripemd).slice(2, 10);
      const subAddress = ripemd + checksum;

      const newSub = { index: saltedIndex, address: subAddress, locked: false, balance: '0' };
      setSubWallets(prev => [...prev, newSub]);
      setSubIndex(prev => prev + 1);

      toast.success('Sub-wallet created!');
      await refreshSubBalance(subAddress);
    } catch (err) {
      toast.error('Failed to generate sub-wallet');
    }
  };

  const regenerateSubWallet = async () => {
    if (!mainMnemonic) return toast.error('Main mnemonic required');
    if (!regenIndex || isNaN(regenIndex)) return toast.error('Enter a valid index number');

    const saltedIndex = Number(regenIndex);
    const path = `m/44'/2070'/0'/0/${saltedIndex}'`;

    try {
      const hdNode = ethers.utils.HDNode.fromMnemonic(mainMnemonic).derivePath(path);
      const publicKey = hdNode.publicKey.slice(2);
      const sha = ethers.utils.sha256('0x' + publicKey).slice(2);
      const ripemd = ethers.utils.ripemd160('0x' + sha).slice(2);
      const checksum = ethers.utils.sha256('0x' + ripemd).slice(2, 10);
      const subAddress = ripemd + checksum;

      // Replace or add the regenerated wallet
      setSubWallets(prev => {
        const filtered = prev.filter(s => s.index !== saltedIndex);
        return [...filtered, { index: saltedIndex, address: subAddress, locked: false, balance: '0' }];
      });

      // If it was the last one or higher, update subIndex if needed
      if (saltedIndex >= subIndex) {
        setSubIndex(saltedIndex + 1);
      }

      toast.success('Sub-wallet regenerated!');
      await refreshSubBalance(subAddress);
      setRegenIndex(''); // clear input
    } catch (err) {
      toast.error('Failed to regenerate sub-wallet');
    }
  };

  const depositToSub = async (sub) => {
    const amount = subDeposits[sub.index]?.trim();
    if (!amount || isNaN(amount) || Number(amount) <= 0) {
      return toast.error('Enter a valid amount');
    }

    setIsDepositing(prev => ({ ...prev, [sub.index]: true }));
    setLoading(true);
    const toastId = toast.loading('Processing deposit...');

    try {
      const txData = await sendTransaction(
        mainWallet.privateKey,
        mainWallet.address,
        sub.address,
        amount,
        '0.01'
      );

      const txHash = txData?.data?.txHash || txData?.txHash || txData?.hash;
      if (!txHash) throw new Error('No tx hash received');

      toast.success('Deposit sent! Securing wallet...', { id: toastId });

      setSubWallets(prev =>
        prev.map(s =>
          s.index === sub.index
            ? { ...s, balance: (Number(s.balance || 0) + Number(amount)).toFixed(8) }
            : s
        )
      );

      setSubDeposits(prev => ({ ...prev, [sub.index]: '' }));
      setSubTxHashes(prev => ({ ...prev, [sub.index]: txHash }));

      const locked = await lockSubWithProof(sub, txHash);
      if (locked) {
        toast.success('Deposit & lock completed!', { id: toastId });
      } else {
        toast.warning('Deposit OK — auto-lock failed. Try again later.', { id: toastId });
      }

      await refreshSubBalance(sub.address);
    } catch (err) {
      toast.error('Deposit failed: ' + err.message, { id: toastId });
    } finally {
      setIsDepositing(prev => ({ ...prev, [sub.index]: false }));
      setLoading(false);
      setAutoLockPhase(prev => ({ ...prev, [sub.index]: null }));
    }
  };

  const lockSubWithProof = async (sub, txHashOverride) => {
    const txHash = txHashOverride || subTxHashes[sub.index] || '';
    if (!txHash) {
      toast.error('No transaction hash available');
      return false;
    }

    setAutoLockPhase(prev => ({ ...prev, [sub.index]: 'preparing' }));

    const delays = [6000, 8000, 10000, 12000, 15000, 20000];

    for (let attempt = 0; attempt < delays.length; attempt++) {
      await new Promise(r => setTimeout(r, delays[attempt]));
      setAutoLockPhase(prev => ({ ...prev, [sub.index]: 'fetching' }));

      try {
        const proof = await getWartTxProof(txHash);
        console.log('Proof fetched:', {
          to: proof?.transaction?.toAddress,
          from: proof?.transaction?.fromAddress,
          value: proof?.transaction?.value?.toString()
        });

        setAutoLockPhase(prev => ({ ...prev, [sub.index]: 'confirming' }));

        await send({
          type: 'sub_lock',
          subAddress: sub.address,
          proof,
          recipient: l1Address, // UPDATED: Use L1 MetaMask address
        });

        const confirmed = await pollForLockNotice(sub.address, 45000);
        if (confirmed) {
          setSubWallets(prev =>
            prev.map(s => s.index === sub.index ? { ...s, locked: true } : s)
          );
          setAutoLockPhase(prev => ({ ...prev, [sub.index]: null }));
          return true;
        }
      } catch (err) {
        console.warn(`Proof attempt ${attempt + 1} failed:`, err.message);
      }
    }

    setAutoLockPhase(prev => ({ ...prev, [sub.index]: null }));
    toast.error('Auto-lock timed out — try manual lock later');
    return false;
  };
const withdrawToMain = async (sub) => {
  const amountStr = subWithdrawAmounts[sub.index] || '';
  const fee = subWithdrawFees[sub.index] || '0.01';

  let amount = amountStr === 'max' ? sub.balance : amountStr;

  if (!amount || isNaN(amount) || Number(amount) <= 0) {
    return toast.error('Enter a valid amount');
  }
  if (Number(amount) > Number(sub.balance || 0)) {
    return toast.error('Insufficient balance');
  }

  setIsWithdrawing(prev => ({ ...prev, [sub.index]: true }));
  setLoading(true);
  const toastId = toast.loading('Processing withdrawal...');

  try {
    if (!mainMnemonic) throw new Error('Main mnemonic required');

    const path = `m/44'/2070'/0'/0/${sub.index}'`;
    const hdNode = ethers.utils.HDNode.fromMnemonic(mainMnemonic).derivePath(path);
    
    // FIX: Remove '0x' prefix if present → send raw hex
    let subPrivateKey = hdNode.privateKey;
    if (subPrivateKey.startsWith('0x')) {
      subPrivateKey = subPrivateKey.slice(2);
    }

    const txData = await sendTransaction(
      subPrivateKey,           // ← now raw hex without 0x
      sub.address,
      address,                 // main wallet address
      amount,
      fee
    );

    const txHash = txData?.data?.txHash || txData?.txHash || txData?.hash;
    if (!txHash) throw new Error('No tx hash received');

    toast.success('Withdrawal sent!', { id: toastId });

    setSubWallets(prev =>
      prev.map(s =>
        s.index === sub.index
          ? { ...s, balance: (Number(s.balance || 0) - Number(amount)).toFixed(8) }
          : s
      )
    );

    setSubWithdrawAmounts(prev => ({ ...prev, [sub.index]: '' }));
    setSubWithdrawFees(prev => ({ ...prev, [sub.index]: '0.01' }));

    setTimeout(async () => {
      await refreshSubBalance(sub.address);
    }, 4000);

  } catch (err) {
    console.error('Withdraw error:', err);
    toast.error('Withdrawal failed: ' + (err.message || 'Unknown error'), { id: toastId });
  } finally {
    setIsWithdrawing(prev => ({ ...prev, [sub.index]: false }));
    setLoading(false);
  }
};
  const setMaxWithdraw = (sub) => {
    setSubWithdrawAmounts(prev => ({
      ...prev,
      [sub.index]: sub.balance || '0'
    }));
  };

  const pollForLockNotice = async (subAddress, timeoutMs = 45000) => {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
      try {
        const { notices } = await client.request(gql`
          { notices(last: 5) { edges { node { payload } } } }
        `);
        const parsed = notices.edges
          .map(e => {
            try { return JSON.parse(ethers.utils.toUtf8String(e.node.payload)); }
            catch { return null; }
          })
          .filter(Boolean);
        if (parsed.some(n => n.type === 'subwallet_locked' && n.subAddress === subAddress && n.verified)) {
          return true;
        }
      } catch {}
      await new Promise(r => setTimeout(r, 2000));
    }
    return false;
  };

  const pollForUnlockNotice = async (subAddress, timeoutMs = 45000) => {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
      try {
        const { notices } = await client.request(gql`
          { notices(last: 5) { edges { node { payload } } } }
        `);
        const parsed = notices.edges
          .map(e => {
            try { return JSON.parse(ethers.utils.toUtf8String(e.node.payload)); }
            catch { return null; }
          })
          .filter(Boolean);
        if (parsed.some(n => n.type === 'subwallet_unlocked' && n.subAddress === subAddress && n.verified)) {
          return true;
        }
      } catch {}
      await new Promise(r => setTimeout(r, 2000));
    }
    return false;
  };

  const isSubLocked = async (subAddress) => {
    try {
      const { notices } = await client.request(gql`
        { notices(last: 20) { edges { node { payload } } } }
      `);
      const parsed = notices.edges
        .map(e => {
          try { return JSON.parse(ethers.utils.toUtf8String(e.node.payload)); }
          catch { return null; }
        })
        .filter(Boolean);
      const relevant = parsed.filter(
        n => n.subAddress === subAddress && n.verified && ['subwallet_locked', 'subwallet_unlocked'].includes(n.type)
      );
      return relevant.length > 0 && relevant[0].type === 'subwallet_locked';
    } catch {
      return false;
    }
  };

 const requestUnlock = async (sub) => {
  setIsUnlocking(prev => ({ ...prev, [sub.index]: true }));
  setLoading(true); // optional — depends if you want global loading too

  const toastId = toast.loading('Requesting unlock...');

  try {
    await send({ type: 'sub_unlock', subAddress: sub.address });

    toast.loading('Waiting for unlock confirmation...', { id: toastId });

    const unlocked = await pollForUnlockNotice(sub.address); // ← give it a bit more time if needed

    if (unlocked) {
      setSubWallets(prev =>
        prev.map(s => s.index === sub.index ? { ...s, locked: false } : s)
      );
      toast.success('Sub-wallet unlocked!', { id: toastId });
    } else {
      toast.error('Unlock not confirmed in time', { id: toastId });
    }
  } catch (err) {
    toast.error('Unlock request failed: ' + err.message, { id: toastId });
  } finally {
    setIsUnlocking(prev => ({ ...prev, [sub.index]: false }));
    setLoading(false);
  }
};

  const refreshSubBalance = async (subAddress) => {
    try {
      const { balance } = await fetchBalanceAndNonce(subAddress, true);
      const locked = await isSubLocked(subAddress);
      setSubWallets(prev =>
        prev.map(sub =>
          sub.address === subAddress ? { ...sub, balance: balance || '0', locked } : sub
        )
      );
      toast.success('Balance & lock state refreshed', { duration: 2000 });
    } catch {
      toast.error('Failed to refresh');
    }
  };

  const getLockStatusText = (phase) => {
    if (phase === 'preparing') return 'Preparing proof (may take a few minutes)';
    if (phase === 'fetching')   return 'Waiting for Cartesi to index transaction';
    if (phase === 'confirming') return 'Submitting lock & waiting for confirmation';
    return 'Securing sub-wallet...';
  };

return (
  <section className="subwallet-section">
    <h3>Sub-Wallets (Locked with Cartesi Proofs)</h3>

    <div className="subwallet-controls">
      <button
        onClick={generateLockedSubWallet}
        disabled={loading}
        className="btn btn-primary"
      >
        + Generate New Sub-Wallet
      </button>

      <div className="regen-group">
        <input
          type="number"
          placeholder="Enter salted index to regenerate"
          value={regenIndex}
          onChange={(e) => setRegenIndex(e.target.value)}
          className="input regen-input"
        />
        <button
          onClick={regenerateSubWallet}
          disabled={loading || !regenIndex}
          className="btn btn-secondary"
        >
          Regenerate
        </button>
      </div>
    </div>

    <ul className="subwallet-list">
      {subWallets.map((sub) => (
        <li
          key={sub.index}
          className={`subwallet-item ${sub.locked ? 'locked' : 'unlocked'}`}
        >
          <div className="subwallet-info">
            <div>
              <strong>Index:</strong> {sub.index}
            </div>
            <div>
              <strong>Address:</strong> {sub.address}
            </div>
            <div>
              <strong>Balance:</strong> {sub.balance ?? '0'} WART
            </div>
            <div>
              <strong>Status:</strong>{' '}
              <span className={sub.locked ? 'status-locked' : 'status-unlocked'}>
                {sub.locked ? 'Locked 🔒' : 'Unlocked 🔓'}
              </span>
            </div>
          </div>

     <div className="subwallet-actions">
  <button
    onClick={() => refreshSubBalance(sub.address)}
    disabled={loading || isUnlocking[sub.index]}
    className="btn btn-outline"
  >
    Refresh
  </button>

  {sub.locked ? (
    <>
      <button
        onClick={() => requestUnlock(sub)}
        disabled={loading || isUnlocking[sub.index]}
        className="btn btn-danger"
      >
        {isUnlocking[sub.index] ? 'Unlocking...' : 'Request Unlock'}
      </button>

      {/* ← moved here: full-width status message below buttons */}
      {isUnlocking[sub.index] && (
        <div className="status-message status-unlock">
          <div className="spinner" />
          <span>
            Requesting unlock & waiting for confirmation
            <LoadingDots />
          </span>
        </div>
      )}
    </>
            ) : (
              <>
                {/* Deposit */}
                <div className="action-group deposit-group">
                  <input
                    type="number"
                    step="0.00000001"
                    placeholder="Deposit amount"
                    value={subDeposits[sub.index] || ''}
                    onChange={(e) =>
                      setSubDeposits((prev) => ({ ...prev, [sub.index]: e.target.value }))
                    }
                    disabled={isDepositing[sub.index] || loading}
                    className="input amount-input"
                  />
                  <button
                    onClick={() => depositToSub(sub)}
                    disabled={isDepositing[sub.index] || loading}
                    className="btn btn-success"
                  >
                    {isDepositing[sub.index] ? 'Processing...' : 'Deposit & Auto-Lock'}
                  </button>
                </div>

                {/* Withdraw */}
                <div className="action-group withdraw-group">
                  <input
                    type="number"
                    step="0.00000001"
                    placeholder="Withdraw amount"
                    value={subWithdrawAmounts[sub.index] || ''}
                    onChange={(e) =>
                      setSubWithdrawAmounts((prev) => ({ ...prev, [sub.index]: e.target.value }))
                    }
                    disabled={
                      isWithdrawing[sub.index] ||
                      loading ||
                      !sub.balance ||
                      Number(sub.balance) <= 0
                    }
                    className="input amount-input"
                  />
                  <button
                    onClick={() => setMaxWithdraw(sub)}
                    disabled={
                      isWithdrawing[sub.index] ||
                      loading ||
                      !sub.balance ||
                      Number(sub.balance) <= 0
                    }
                    className="btn btn-info small"
                  >
                    Max
                  </button>
                  <button
                    onClick={() => withdrawToMain(sub)}
                    disabled={
                      isWithdrawing[sub.index] ||
                      loading ||
                      !sub.balance ||
                      Number(sub.balance) <= 0
                    }
                    className="btn btn-primary"
                  >
                    {isWithdrawing[sub.index] ? 'Sending...' : 'Withdraw to Main'}
                  </button>
                </div>
              </>
            )}
          </div>

          {/* Status feedback messages */}
          {(isDepositing[sub.index] || autoLockPhase[sub.index]) && (
            <div className="status-message status-deposit">
              <div className="spinner" />
              <span>
                {getLockStatusText(autoLockPhase[sub.index])}
                <LoadingDots />
              </span>
            </div>
          )}

          {isWithdrawing[sub.index] && (
            <div className="status-message status-withdraw">
              <div className="spinner" />
              <span>
                Sending to main wallet
                <LoadingDots />
              </span>
            </div>
          )}
        </li>
      ))}
    </ul>

    {subError && <div className="error-message">{subError}</div>}

    <Toaster position="top-right" />
  </section>
);
}

export default SubWallet;
