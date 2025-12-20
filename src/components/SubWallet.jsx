// src/components/SubWallet.jsx
// README: This component manages the creation, locking, and unlocking of sub-wallets derived from the main Warthog wallet using a Cartesi-dynamic salt for uniqueness and proof-tied functionality. It handles generation, deposits from main, submitting lock proofs to Cartesi, and unlocking via vouchers. States are local to this component, and it receives props from WarthogWallet for integration with sending, balance fetching, and Cartesi 'send'. Use this for self-custodial locked balances verifiable by Cartesi proofs.

import { useState } from 'react'; // For useState
import { gql, GraphQLClient } from 'graphql-request'; // For GraphQL
import { ethers } from 'ethers';
import { Toaster, toast } from 'react-hot-toast'; // If needed for local toasts

// NEW: Define GRAPHQL_URL here (moved from parent to avoid reference error)
const GRAPHQL_URL = 'http://localhost:8080/graphql'; // Update to your Cartesi GraphQL endpoint

function SubWallet({
  mainWallet,
  mainMnemonic,
  selectedNode,
  fetchBalanceAndNonce,
  sendTransaction,
  send, // Cartesi send
  address, // L1 address
  loading,
  setLoading,
  subWallets,
  setSubWallets,
  subIndex,
  setSubIndex,
  subDepositAmt,
  setSubDepositAmt,
  selectedSub,
  setSelectedSub,
  voucherPayload,
  setVoucherPayload,
  setWartToAddr,
  setWartAmount,
  setWartFee,
  getWartTxProof
}) {
  const [subError, setSubError] = useState(null);
  const [subSalt, setSubSalt] = useState(null);
  const client = new GraphQLClient(GRAPHQL_URL);

  // NEW for relay in SubWallet (moved from parent for independence)
  const [wartTxHashForRelay, setWartTxHashForRelay] = useState('');

  // NEW for regeneration
  const [regenIndex, setRegenIndex] = useState('');

  // Fetch dynamic salt from Cartesi notice
  const fetchCartesiSalt = async (userMainAddress) => {
    try {
      const query = gql`{ notices(last: 1) { edges { node { payload } } } }`; // Customize to stable notice
      const data = await client.request(query);
      const noticePayload = data.notices.edges[0]?.node.payload || 'fallback_genesis_hash';
      const timestamp = Math.floor(Date.now() / 1000);
      const composite = ethers.utils.keccak256(ethers.utils.toUtf8Bytes(noticePayload + userMainAddress + timestamp.toString()));
      setSubSalt(composite);
      return composite;
    } catch (err) {
      setSubError('Failed to fetch Cartesi salt');
      return 'fallback_salt'; // Hardcoded fallback
    }
  };

  // Generate locked sub-wallet with dynamic salt
  const generateLockedSubWallet = async (index) => {
    if (!mainMnemonic) {
      setSubError('Main wallet mnemonic required for derivation');
      toast.error('Main wallet mnemonic required for derivation'); // Added toast for visibility
      return;
    }
    const salt = await fetchCartesiSalt(mainWallet.address);
    const saltedIndex = index + parseInt(salt.slice(2, 10), 16) % (2**31 - 1);
    const path = `m/44'/2070'/0'/0/${saltedIndex}'`; // Hardened, custom coin type for Warthog/Cartesi
    try {
      const hdNode = ethers.utils.HDNode.fromMnemonic(mainMnemonic).derivePath(path);
      const publicKey = hdNode.publicKey.slice(2);
      const sha = ethers.utils.sha256('0x' + publicKey).slice(2);
      const ripemd = ethers.utils.ripemd160('0x' + sha).slice(2);
      const checksum = ethers.utils.sha256('0x' + ripemd).slice(2, 10);
      const subAddress = ripemd + checksum;
      const subMnemonic = mainMnemonic; // Use main mnemonic for derivation; sub doesn't have separate mnemonic
      const subPrivKey = hdNode.privateKey.slice(2);
      const newSub = { index: saltedIndex, address: subAddress, mnemonic: subMnemonic, privKey: subPrivKey, locked: true, voucher: null, balance: '0' };
      setSubWallets([...subWallets, newSub]);
      setSubIndex(index + 1);
      toast.success('Sub-wallet generated!');
      // Optionally save encrypted
    } catch (err) {
      setSubError('Failed to generate sub-wallet');
      toast.error('Failed to generate sub-wallet');
    }
  };

  // Regenerate specific sub-wallet
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
      const subPrivKey = hdNode.privateKey.slice(2);
      const regeneratedSub = { index: saltedIndex, address: subAddress, mnemonic: mainMnemonic, privKey: subPrivKey, locked: true, voucher: null, balance: '0' };
      setSubWallets(prev => [...prev.filter(sub => sub.index !== saltedIndex), regeneratedSub]);
      toast.success('Sub-wallet regenerated!');
    } catch (err) {
      setSubError('Failed to regenerate sub-wallet');
      toast.error('Failed to regenerate sub-wallet');
    }
  };

  // Deposit to sub-address (send from main)
  const depositToSub = async () => {
    if (!subDepositAmt || !selectedSub) return setSubError('Select sub-wallet and enter amount');
    setLoading(true);
    try {
      setWartToAddr(selectedSub.address);
      setWartAmount(subDepositAmt);
      setWartFee('0.01');
      await sendTransaction(); // Use Warthog send
      toast.success('Deposited to sub-wallet! Submit tx proof to Cartesi for lock.');
      // Update sub balance
      const updatedSubs = subWallets.map(sub => sub.index === selectedSub.index ? { ...sub, balance: (parseFloat(sub.balance) + parseFloat(subDepositAmt)).toString() } : sub);
      setSubWallets(updatedSubs);
      setSubDepositAmt('');
    } catch (err) {
      setSubError('Deposit failed');
      toast.error('Deposit failed');
    } finally {
      setLoading(false);
    }
  };

  // Submit deposit tx proof to Cartesi for lock
  const lockSubWithProof = async (txHash) => {
    if (!txHash || !selectedSub) return setSubError('Enter tx hash and select sub');
    setLoading(true);
    try {
      const proof = await getWartTxProof(txHash); // Use existing getWartTxProof
      const payload = { type: 'sub_lock', subAddress: selectedSub.address, proof, recipient: address };
      await send(payload); // Cartesi input
      toast.success('Lock proof submitted! Sub-wallet locked until voucher unlock.');
    } catch (err) {
      setSubError('Lock failed');
      toast.error('Lock failed');
    } finally {
      setLoading(false);
    }
  };

  // Unlock sub with voucher (manual input for now)
  const unlockSubWithVoucher = () => {
    if (!voucherPayload || !selectedSub) return setSubError('Enter voucher payload and select sub');
    try {
      // Simulate verification (in real, query Cartesi for voucher)
      const updatedSubs = subWallets.map(sub => sub.index === selectedSub.index ? { ...sub, locked: false, voucher: voucherPayload } : sub);
      setSubWallets(updatedSubs);
      toast.success('Sub-wallet unlocked! You can now send from it.');
      setVoucherPayload('');
    } catch (err) {
      setSubError('Unlock failed');
      toast.error('Unlock failed');
    }
  };

  // Fetch sub balance
  const refreshSubBalance = async (subAddress) => {
    await fetchWartBalanceAndNonce(subAddress); // Reuse, but update sub balance
    // Note: This sets main states; for subs, call separately and update subWallets
  };

  // Clear all sub-wallets
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
            Index: {sub.index} | Address: {sub.address} | Balance: {sub.balance} WART | Locked: {sub.locked ? 'Yes' : 'No'}
            <button onClick={() => refreshSubBalance(sub.address)}>Refresh Balance</button>
            <button onClick={() => setSelectedSub(sub)}>Select for Actions</button>
          </li>
        ))}
      </ul>
      {selectedSub && (
        <div>
          <h4>Actions for Selected Sub ({selectedSub.address})</h4>
          <input
            type="number"
            placeholder="Deposit Amount to Sub"
            value={subDepositAmt}
            onChange={(e) => setSubDepositAmt(e.target.value)}
          />
          <button onClick={depositToSub} disabled={loading}>Deposit from Main</button>
          <input
            type="text"
            placeholder="Deposit Tx Hash for Lock Proof"
            value={wartTxHashForRelay}
            onChange={(e) => setWartTxHashForRelay(e.target.value)}
          />
          <button onClick={() => lockSubWithProof(wartTxHashForRelay)} disabled={loading}>Submit Lock Proof</button>
          {selectedSub.locked && (
            <>
              <input
                type="text"
                placeholder="Voucher Payload to Unlock"
                value={voucherPayload}
                onChange={(e) => setVoucherPayload(e.target.value)}
              />
              <button onClick={unlockSubWithVoucher} disabled={loading}>Unlock with Voucher</button>
            </>
          )}
          {!selectedSub.locked && (
            <button onClick={() => {
              setWartToAddr(''); // Set to send from sub, but since sub privkey is available, implement send from sub
              // TODO: Implement send from sub using sub privkey
            }} disabled={loading}>Send from Sub</button>
          )}
        </div>
      )}
      {subError && <div className="error">{subError}</div>}
    </section>
  );
}

export default SubWallet; // Added export default