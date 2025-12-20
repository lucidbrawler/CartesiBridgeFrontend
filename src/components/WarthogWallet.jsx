// src/components/WarthogWallet.jsx
// README: This component handles the Warthog native wallet functionality, including creation, derivation, import, login, balance fetching, transaction sending, and bridging to Cartesi/Liquid. It manages state for wallet data, errors, modals, and integrates with the Warthog node API via proxy. It also includes the relay functions for depositing WART and submitting proofs to Cartesi. This is extracted from the main WalletIsland for modularity, and it receives props like 'send' for Cartesi interactions and 'loading' for UI synchronization.

import { useState, useEffect } from 'react'; // Added for local state/effects
import CryptoJS from 'crypto-js';
import axios from 'axios';
import SubWallet from './SubWallet'; // Import for SubWallet
import { ethers } from 'ethers';
import { Toaster, toast } from 'react-hot-toast'; // If needed for local toasts

// WARTHOG CONFIG (moved from WalletIsland)
const API_URL = '/api/proxy'; // Your proxy for Warthog RPC (or adjust for Astro routes if needed)
const defaultNodeList = [
  'https://warthognode.duckdns.org',
  'http://217.182.64.43:3001',
  'http://65.87.7.86:3001',
  // Add more
];
const BRIDGE_ADDRESS = 'YourWarthogBridgeAddressHere'; // Warthog bridge/multisig addr for deposits

function WarthogWallet({ send, address, loading, setLoading }) {
  // STATES FROM wallet.jsx (Warthog-specific, prefixed)
  const [wartDeferredPrompt, setWartDeferredPrompt] = useState(null);
  const [wartWalletData, setWartWalletData] = useState(null);
  const [wartShowModal, setWartShowModal] = useState(false);
  const [wartConsentToClose, setWartConsentToClose] = useState(false);
  const [wartValidateResult, setWartValidateResult] = useState(null);
  const [wartSendResult, setWartSendResult] = useState(null);
  const [wartWallet, setWartWallet] = useState(null);
  const [wartBalance, setWartBalance] = useState(null);
  const [wartNonceId, setWartNonceId] = useState(null);
  const [wartPinHeight, setWartPinHeight] = useState(null);
  const [wartPinHash, setWartPinHash] = useState(null);
  const [wartMnemonic, setWartMnemonic] = useState('');
  const [wartPrivateKeyInput, setWartPrivateKeyInput] = useState('');
  const [wartAddress, setWartAddress] = useState('');
  const [wartToAddr, setWartToAddr] = useState('');
  const [wartAmount, setWartAmount] = useState('');
  const [wartFee, setWartFee] = useState('0.01');
  const [wartWordCount, setWartWordCount] = useState('12');
  const [wartPathType, setWartPathType] = useState('hardened');
  const [wartAction, setWartAction] = useState('create');
  const [wartError, setWartError] = useState(null);
  const [wartPassword, setWartPassword] = useState('');
  const [wartSaveConsent, setWartSaveConsent] = useState(false);
  const [wartShowPasswordPrompt, setWartShowPasswordPrompt] = useState(false);
  const [wartUploadedFile, setWartUploadedFile] = useState(null);
  const [wartIsWalletProcessed, setWartIsWalletProcessed] = useState(false);
  const [wartIsLoggedIn, setWartIsLoggedIn] = useState(false);
  const [wartSelectedNode, setWartSelectedNode] = useState(defaultNodeList[0]);
  const [wartShowDownloadPrompt, setWartShowDownloadPrompt] = useState(false);

  // NEW for relay
  const [wartTxHashForRelay, setWartTxHashForRelay] = useState('');

  // NEW for SubWallet
  const [subWallets, setSubWallets] = useState([]); // List of generated sub-wallets {index, address, locked: true, voucher: null, balance: '0'}
  const [subIndex, setSubIndex] = useState(0); // For new sub-wallet index
  const [subDepositAmt, setSubDepositAmt] = useState(''); // For depositing to sub-address
  const [selectedSub, setSelectedSub] = useState(null); // For unlocking a specific sub
  const [voucherPayload, setVoucherPayload] = useState(''); // For manual voucher input to unlock

  // Persist subWallets and subIndex
  useEffect(() => {
    if (wartIsLoggedIn) {
      const storedSubs = localStorage.getItem('warthogSubWallets');
      if (storedSubs) {
        const parsedSubs = JSON.parse(storedSubs);
        setSubWallets(parsedSubs);
        const maxIndex = parsedSubs.length > 0 ? Math.max(...parsedSubs.map(sub => sub.index)) + 1 : 0;
        setSubIndex(maxIndex);
      }
    }
  }, [wartIsLoggedIn]);

  useEffect(() => {
    if (wartIsLoggedIn && subWallets.length > 0) {
      localStorage.setItem('warthogSubWallets', JSON.stringify(subWallets));
    }
  }, [subWallets, wartIsLoggedIn]);

  // WARTHOG useEffects (from wallet.jsx)
  useEffect(() => {
    const handleBeforeInstallPrompt = (e) => {
      e.preventDefault();
      setWartDeferredPrompt(e);
    };

    window.addEventListener('beforeinstallprompt', handleBeforeInstallPrompt);

    return () => {
      window.removeEventListener('beforeinstallprompt', handleBeforeInstallPrompt);
    };
  }, []);

  useEffect(() => {
    const handleAppInstalled = () => {
      setWartDeferredPrompt(null);
    };

    window.addEventListener('appinstalled', handleAppInstalled);

    return () => {
      window.removeEventListener('appinstalled', handleAppInstalled);
    };
  }, []);

  useEffect(() => {
    const encryptedWallet = localStorage.getItem('warthogWallet');
    if (encryptedWallet) {
      setWartShowPasswordPrompt(true);
    }
  }, []);

  useEffect(() => {
    if (wartWallet?.address) {
      console.log('Fetching balance for address:', wartWallet.address);
      fetchWartBalanceAndNonce(wartWallet.address);
    }
  }, [wartWallet, wartSelectedNode]);

  useEffect(() => {
    if (wartShowModal) {
      window.alert("If you haven't backed up the information elsewhere, do not close the next window without saving or downloading your private key.");
    }
  }, [wartShowModal]);

  // WARTHOG FUNCTIONS (from wallet.jsx)
  const wartToE8 = (wart) => {
    try {
      const num = parseFloat(wart);
      if (isNaN(num) || num <= 0) return null;
      return Math.round(num * 100000000);
    } catch {
      return null;
    }
  };

  const fetchWartBalanceAndNonce = async (address) => {
    setWartError(null);
    setWartBalance(null);
    setWartNonceId(null);
    setWartPinHeight(null);
    setWartPinHash(null);

    try {
      const nodeBaseParam = `nodeBase=${encodeURIComponent(wartSelectedNode)}`;
      console.log('Sending chain head request to:', `${API_URL}?nodePath=chain/head&${nodeBaseParam}`);
      const chainHeadResponse = await axios.get(`${API_URL}?nodePath=chain/head&${nodeBaseParam}`, {
        headers: { 'Content-Type': 'application/json' },
      });
      console.log('Chain head response status:', chainHeadResponse.status);
      const chainHeadData = chainHeadResponse.data.data || chainHeadResponse.data;
      console.log('Chain head response data:', chainHeadData);

      setWartPinHeight(chainHeadData.pinHeight);
      setWartPinHash(chainHeadData.pinHash);

      console.log('Sending balance request to:', `${API_URL}?nodePath=account/${address}/balance&${nodeBaseParam}`);
      const balanceResponse = await axios.get(`${API_URL}?nodePath=account/${address}/balance&${nodeBaseParam}`, {
        headers: { 'Content-Type': 'application/json' },
      });
      console.log('Balance response status:', balanceResponse.status);
      const balanceData = balanceResponse.data.data || balanceResponse.data;
      console.log('Balance response data:', balanceData);

      const balanceInWart = balanceData.balance !== undefined ? (balanceData.balance / 100000000).toFixed(8) : '0';
      setWartBalance(balanceInWart);

      if (balanceData.nonceId !== undefined) {
        const nonce = Number(balanceData.nonceId);
        if (isNaN(nonce) || nonce < 0 || nonce > 4294967295) {
          throw new Error('Invalid nonceId: must be a 32-bit unsigned integer');
        }
        setWartNonceId(Number(balanceData.nonceId) + 1 || 0);
      } else {
        setWartNonceId(0);
      }

      console.log('Chain head data:', chainHeadData);
    } catch (err) {
      const errorMessage =
        err.response?.data?.message ||
        err.message ||
        'Could not fetch chain head or balance';
      setWartError(errorMessage);
      console.error('Fetch error:', err);
    }
  };

  const encryptWartWallet = (walletData, password) => {
    const { privateKey, publicKey, address, mnemonic } = walletData;
    const walletToSave = { privateKey, publicKey, address, mnemonic };
    const encrypted = CryptoJS.AES.encrypt(JSON.stringify(walletToSave), password).toString();
    return encrypted;
  };

  const decryptWartWallet = (encrypted, password) => {
    try {
      const bytes = CryptoJS.AES.decrypt(encrypted, password);
      const decrypted = bytes.toString(CryptoJS.enc.Utf8);
      if (!decrypted) throw new Error('Invalid password');
      return JSON.parse(decrypted);
    } catch {
      throw new Error('Failed to decrypt wallet: Invalid password');
    }
  };

  const saveWartWallet = (walletData) => {
    if (!wartSaveConsent || !wartPassword) {
      setWartError('Please provide a password and consent to save the wallet');
      return false;
    }
    try {
      const encrypted = encryptWartWallet(walletData, wartPassword);
      localStorage.setItem('warthogWallet', encrypted);
      setWartWallet(walletData);
      setWartShowPasswordPrompt(false);
      setWartError(null);
      setWartIsWalletProcessed(true);
      setWartIsLoggedIn(true); // Added to log in after saving
      setWartPassword('');
      setWartSaveConsent(false);
      return true;
    } catch (err) {
      setWartError(err.message);
      return false;
    }
  };

  const downloadWartWallet = (walletData) => {
    if (!wartPassword) {
      setWartError('Please provide a password to encrypt the wallet file');
      return;
    }
    const encrypted = encryptWartWallet(walletData, wartPassword);
    const blob = new Blob([encrypted], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'warthog_wallet.txt';
    a.click();
    URL.revokeObjectURL(url);
    setWartWallet(walletData); // Added to set wallet in memory
    setWartIsWalletProcessed(true);
    setWartIsLoggedIn(true); // Added to log in after downloading
    setWartPassword('');
    setWartSaveConsent(false);
  };

  const handleWartFileUpload = (event) => {
    const file = event.target.files[0];
    if (!file) {
      setWartError('No file selected');
      return;
    }
    const reader = new FileReader();
    reader.onload = (e) => {
      setWartUploadedFile(e.target.result);
    };
    reader.onerror = () => setWartError('Failed to read file');
    reader.readAsText(file);
  };

  const loadWartWallet = () => {
    if (!wartPassword) {
      setWartError('Please provide a password');
      return;
    }
    try {
      let encrypted;
      if (wartUploadedFile) {
        encrypted = wartUploadedFile;
      } else {
        encrypted = localStorage.getItem('warthogWallet');
        if (!encrypted) throw new Error('No wallet found in storage or file');
      }
      const decryptedWallet = decryptWartWallet(encrypted, wartPassword);
      setWartWallet(decryptedWallet);
      setWartShowPasswordPrompt(false);
      setWartUploadedFile(null);
      setWartError(null);
      setWartIsWalletProcessed(false);
      setWartIsLoggedIn(true);
    } catch (err) {
      setWartError(err.message);
    }
  };

  const clearWartWallet = () => {
    localStorage.removeItem('warthogWallet');
    localStorage.removeItem('warthogSubWallets');
    setWartWallet(null);
    setWartBalance(null);
    setWartNonceId(null);
    setWartPinHeight(null);
    setWartPinHash(null);
    setWartError(null);
    setWartPassword('');
    setWartSaveConsent(false);
    setWartUploadedFile(null);
    setWartIsWalletProcessed(false);
    setWartIsLoggedIn(false);
    setSubWallets([]);
    setSubIndex(0);
  };

  const generateWartWallet = async (wordCount, pathType) => {
    const strengthBytes = wordCount === 12 ? 16 : 32;
    const entropy = window.crypto.getRandomValues(new Uint8Array(strengthBytes));
    const mnemonic = ethers.utils.entropyToMnemonic(ethers.utils.hexlify(entropy));
    const path = pathType === 'hardened' ? "m/44'/2070'/0'/0/0" : "m/44'/2070'/0/0/0";
    const hdNode = ethers.utils.HDNode.fromMnemonic(mnemonic).derivePath(path);
    const publicKey = ethers.utils.computePublicKey(hdNode.privateKey, true).slice(2);
    const sha = ethers.utils.sha256('0x' + publicKey).slice(2);
    const ripemd = ethers.utils.ripemd160('0x' + sha).slice(2);
    const checksum = ethers.utils.sha256('0x' + ripemd).slice(2, 10);
    const address = ripemd + checksum;
    if (address.length !== 48) {
      throw new Error('Generated address has invalid length');
    }
    return {
      mnemonic,
      wordCount,
      pathType,
      privateKey: hdNode.privateKey.slice(2),
      publicKey,
      address,
    };
  };

const deriveWartWallet = (mnemonic, wordCount, pathType) => {
  try {
    const words = mnemonic.trim().split(/\s+/);
    const expectedWordCount = Number(wordCount);
    if (words.length !== expectedWordCount) {
      throw new Error(`Invalid mnemonic: must have exactly ${expectedWordCount} words`);
    }
    const path = pathType === 'hardened' ? "m/44'/2070'/0'/0/0" : "m/44'/2070'/0/0/0";
    const hdNode = ethers.utils.HDNode.fromMnemonic(mnemonic).derivePath(path);
    const publicKey = ethers.utils.computePublicKey(hdNode.privateKey, true).slice(2);
    const sha = ethers.utils.sha256('0x' + publicKey).slice(2);
    const ripemd = ethers.utils.ripemd160('0x' + sha).slice(2);
    const checksum = ethers.utils.sha256('0x' + ripemd).slice(2, 10);
    const address = ripemd + checksum;
    if (address.length !== 48) {
      throw new Error('Generated address has invalid length');
    }
    return {
      mnemonic,
      wordCount,
      pathType,
      privateKey: hdNode.privateKey.slice(2),
      publicKey,
      address,
    };
  } catch (err) {
    throw new Error('Invalid mnemonic');
  }
};

const importWartFromPrivateKey = (privKey) => {
  try {
    const publicKey = ethers.utils.computePublicKey('0x' + privKey, true).slice(2);
    const sha = ethers.utils.sha256('0x' + publicKey).slice(2);
    const ripemd = ethers.utils.ripemd160('0x' + sha).slice(2);
    const checksum = ethers.utils.sha256('0x' + ripemd).slice(2, 10);
    const address = ripemd + checksum;
    if (address.length !== 48) {
      throw new Error('Generated address has invalid length');
    }
    return {
      privateKey: privKey,
      publicKey,
      address,
    };
  } catch (err) {
    throw new Error('Invalid private key');
  }
};

  const handleWartAction = async () => {
    setWartError(null);
    setWartIsWalletProcessed(false);

    if (wartAction === 'login' && !wartUploadedFile) {
      setWartError('Please upload the warthog_wallet.txt file');
      return;
    }

    if (wartAction === 'login') {
      loadWartWallet();
      return;
    }

    if (wartAction === 'derive' && !wartMnemonic) {
      setWartError('Please enter a seed phrase');
      return;
    }

    if (wartAction === 'import' && !wartPrivateKeyInput) {
      setWartError('Please enter a private key');
      return;
    }

    if (wartAction === 'derive') {
      const words = wartMnemonic.trim().split(/\s+/);
      const expectedWordCount = Number(wartWordCount);
      if (words.length !== expectedWordCount) {
        setWartError(`Seed phrase must have exactly ${expectedWordCount} words`);
        return;
      }
    }

    try {
      let data;
      if (wartAction === 'create') {
        data = await generateWartWallet(Number(wartWordCount), wartPathType);
      } else if (wartAction === 'derive') {
        data = deriveWartWallet(wartMnemonic, Number(wartWordCount), wartPathType);
      } else if (wartAction === 'import') {
        data = importWartFromPrivateKey(wartPrivateKeyInput);
      }
      setWartWalletData(data);
      setWartShowModal(true);
      setWartConsentToClose(false);
    } catch (err) {
      const errorMessage = err.message || `Failed to ${wartAction} wallet`;
      setWartError(errorMessage);
      clearWartWallet();
      console.error(`Wallet action error:`, err);
    }
  };

  const validateWartAddress = (addr) => {
    if (typeof addr !== 'string' || addr.length !== 48) {
      return { valid: false };
    }
    const ripemdHex = addr.slice(0, 40);
    const checksumHex = addr.slice(40);
    const computedChecksum = ethers.utils.sha256('0x' + ripemdHex).slice(2, 10);
    return { valid: computedChecksum === checksumHex };
  };

  const handleValidateWartAddress = () => {
    setWartError(null);
    setWartValidateResult(null);
    if (!wartAddress) {
      setWartError('Please enter an address');
      return;
    }
    try {
      const result = validateWartAddress(wartAddress);
      setWartValidateResult(result);
    } catch (err) {
      const errorMessage = err.message || 'Failed to validate address';
      setWartError(errorMessage);
      console.error('Validate error:', err);
    }
  };

  const getRoundedFeeE8 = async (feeWart) => {
    const nodeBaseParam = `nodeBase=${encodeURIComponent(wartSelectedNode)}`;
    try {
      const response = await axios.get(`${API_URL}?nodePath=tools/encode16bit/from_string/${feeWart}&${nodeBaseParam}`);
      const feeData = response.data.data || response.data;
      return feeData.roundedE8;
    } catch (err) {
      throw new Error('Failed to round fee');
    }
  };

  const handleSendWartTransaction = async () => {
    setWartError(null);
    setWartSendResult(null);
    if (!wartToAddr || !wartAmount || !wartFee) {
      setWartError('Please fill in all transaction fields');
      return;
    }
    const amountE8 = wartToE8(wartAmount);
    let feeE8;
    try {
      feeE8 = await getRoundedFeeE8(wartFee);
    } catch {
      setWartError('Invalid fee or failed to round');
      return;
    }
    if (!amountE8 || !feeE8) {
      setWartError('Invalid amount or fee: must be positive numbers');
      return;
    }
    const txPrivateKey = wartWallet?.privateKey;
    if (!txPrivateKey) {
      setWartError('No wallet saved. Please create, derive, or log in with a wallet first.');
      return;
    }
    if (wartNonceId === null) {
      setWartError('Nonce not available. Please refresh balance.');
      return;
    }
    if (wartPinHeight === null || wartPinHash === null) {
      setWartError('Chain head not available. Please refresh balance.');
      return;
    }
    try {
      const nonceIdHex = wartNonceId.toString(16).padStart(8, '0');
      const amountHex = amountE8.toString(16).padStart(16, '0');
      const feeHex = feeE8.toString(16).padStart(4, '0');
      const pinHeightHex = wartPinHeight.toString(16).padStart(8, '0');
      const pinHash = wartPinHash.startsWith('0x') ? wartPinHash.slice(2) : wartPinHash;
      const pinHashHex = pinHash.padStart(64, '0');
      const toAddrHex = wartToAddr;
      const payload = nonceIdHex + amountHex + feeHex + pinHeightHex + pinHashHex + toAddrHex;
      if (payload.length % 2 !== 0) {
        throw new Error('Payload has odd length: ' + payload.length);
      }
      const msgHash = ethers.utils.sha256('0x' + payload);
      const msgBytes = ethers.utils.arrayify(msgHash);
      const wallet = new ethers.Wallet('0x' + txPrivateKey);
      const sig = await wallet.signMessage(msgBytes);
      const sigHex = sig.slice(2);
      const txData = {
        nonceId: wartNonceId,
        amount: amountE8,
        fee: feeE8,
        pinHeight: wartPinHeight,
        pinHash: wartPinHash,
        to: wartToAddr,
        sig: sigHex,
      };
      const nodeBaseParam = `nodeBase=${encodeURIComponent(wartSelectedNode)}`;
      console.log('Sending transaction to:', `${API_URL}?nodePath=transaction&${nodeBaseParam}`);
      const response = await axios.post(`${API_URL}?nodePath=transaction&${nodeBaseParam}`, txData, {
        headers: { 'Content-Type': 'application/json' },
      });
      console.log('Transaction response status:', response.status);
      const resultData = response.data.data || response.data;
      console.log('Transaction response data:', resultData);
      setWartSendResult(resultData);
      fetchWartBalanceAndNonce(wartWallet.address);
    } catch (err) {
      const errorMessage =
        err.response?.data?.message ||
        err.message ||
        'Failed to send transaction';
      setWartError(errorMessage);
      console.error('Send error:', err);
    }
  };

  const getWartTxProof = async (txHash) => {
    const nodeBaseParam = `nodeBase=${encodeURIComponent(wartSelectedNode)}`;
    try {
      const response = await axios.get(`${API_URL}?nodePath=transaction/proof/${txHash}&${nodeBaseParam}`);
      return response.data.data || response.data;
    } catch (err) {
      throw new Error('Failed to get tx proof');
    }
  };

  const depositNativeWart = async () => {
    if (!wartAmount) return toast.error('Enter amount');
    setWartToAddr(BRIDGE_ADDRESS);
    setWartFee('0.01'); // Default fee
    await handleSendWartTransaction();
  };

  const relayWartDepositProof = async () => {
    if (!wartTxHashForRelay || !send) return toast.error('Enter Warthog tx hash and connect MetaMask');
    setLoading(true);
    try {
      const proof = await getWartTxProof(wartTxHashForRelay);
      const payload = { type: 'wart_deposit', proof, recipient: address };
      await send(payload); // Uses passed send function for Cartesi input
      toast.success('Proof relayed to Liquid dApp! Voucher pending.');
      setWartTxHashForRelay('');
    } catch (err) {
      toast.error('Relay failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="warthog-section">
      <h2>Warthog Native Wallet & Bridge</h2>
      {wartDeferredPrompt && (
        <button onClick={handleWartInstallClick}>
          Install Wallet App
        </button>
      )}
      {/* Node Selection */}
      <section>
        <h3>Node Selection</h3>
        <div className="form-group">
          <label>Select Node:</label>
          <select
            value={wartSelectedNode}
            onChange={(e) => setWartSelectedNode(e.target.value)}
          >
            {defaultNodeList.map((node, index) => (
              <option key={index} value={node}>
                {node}
              </option>
            ))}
          </select>
        </div>
      </section>

      {wartShowPasswordPrompt && !wartWallet && (
        <section>
          <h3>Unlock Wallet</h3>
          <div className="form-group">
            <label>Upload Wallet File (optional):</label>
            <input type="file" accept=".txt" onChange={handleWartFileUpload} />
          </div>
          <div className="form-group">
            <label>Password:</label>
            <input
              type="password"
              value={wartPassword}
              onChange={(e) => setWartPassword(e.target.value)}
              placeholder="Enter password to unlock wallet"
            />
          </div>
          <button onClick={loadWartWallet}>Unlock Wallet</button>
          <button className="cancel"
            onClick={() => {
              setWartShowPasswordPrompt(false);
              setWartPassword('');
              setWartUploadedFile(null);
            }}
          >
            Cancel
          </button>
        </section>
      )}

      {wartWallet && (
        <section>
          <div style={{display: 'flex', justifyContent: 'space-between', alignItems: 'center'}}>
            <h3>Wallet</h3>
            <button className="download-wallet-btn"
              onClick={() => setWartShowDownloadPrompt(true)}
            >
              Download Wallet File
            </button>
          </div>
          <p className="wallet-address">
            <strong>Address:</strong> {wartWallet.address}
          </p>
          <p>
            <strong>Balance:</strong>{' '}
            {wartBalance !== null ? `${wartBalance} WART` : 'Loading...'}
          </p>
          <button onClick={() => fetchWartBalanceAndNonce(wartWallet.address)}>
            Refresh Balance
          </button>
          <button className="danger" onClick={clearWartWallet}>Clear Wallet</button>
          <p className="warning">
            Warning: Private key is encrypted in localStorage. Keep your password secure.
          </p>
        </section>
      )}

      {wartShowDownloadPrompt && (
        <div className="modal-overlay">
          <div className="modal-content">
            <h3>Download Wallet File</h3>
            <div className="form-group">
              <label>Password to Encrypt Wallet:</label>
              <input
                type="password"
                value={wartPassword}
                onChange={(e) => setWartPassword(e.target.value)}
                placeholder="Enter password to encrypt wallet"
              />
            </div>
            <button onClick={() => { downloadWartWallet(wartWallet); setWartShowDownloadPrompt(false); }}>
              Download
            </button>
            <button className="cancel" onClick={() => { setWartShowDownloadPrompt(false); setWartPassword(''); }}>
              Cancel
            </button>
          </div>
        </div>
      )}

      {!wartIsLoggedIn && (
        <section>
          <h3>Wallet Management</h3>
          <div className="form-group">
            <label>Action:</label>
            <select
              value={wartAction}
              onChange={(e) => {
                setWartAction(e.target.value);
                setWartError(null);
                setWartMnemonic('');
                setWartPrivateKeyInput('');
                setWartUploadedFile(null);
                setWartPassword('');
                setWartIsWalletProcessed(false);
              }}
            >
              <option value="create">Create New Wallet</option>
              <option value="derive">Derive Wallet from Seed Phrase</option>
              <option value="import">Import from Private Key</option>
              <option value="login">Login with Wallet File</option>
            </select>
          </div>
          {wartAction === 'derive' && (
            <div className="form-group">
              <label>Seed Phrase:</label>
              <input
                type="text"
                value={wartMnemonic}
                onChange={(e) => setWartMnemonic(e.target.value)}
                placeholder="Enter 12 or 24-word seed phrase"
              />
            </div>
          )}
          {wartAction === 'import' && (
            <div className="form-group">
              <label>Private Key:</label>
              <input
                type="text"
                value={wartPrivateKeyInput}
                onChange={(e) => setWartPrivateKeyInput(e.target.value.trim())}
                placeholder="Enter 64-character hex private key"
              />
            </div>
          )}
          {wartAction === 'login' && (
            <>
              <div className="form-group">
                <label>Upload Wallet File (warthog_wallet.txt):</label>
                <input
                  type="file"
                  accept=".txt"
                  onChange={handleWartFileUpload}
                />
              </div>
              <div className="form-group">
                <label>Password:</label>
                <input
                  type="password"
                  value={wartPassword}
                  onChange={(e) => setWartPassword(e.target.value)}
                  placeholder="Enter password to decrypt wallet"
                />
              </div>
            </>
          )}
          {(wartAction === 'create' || wartAction === 'derive') && (
            <div className="form-group">
              <label>Word Count:</label>
              <select
                value={wartWordCount}
                onChange={(e) => setWartWordCount(e.target.value)}
              >
                <option value="12">12 Words</option>
                <option value="24">24 Words</option>
              </select>
            </div>
          )}
          {(wartAction === 'create' || wartAction === 'derive') && wartWordCount === '12' && (
            <div className="form-group">
              <label>Derivation Path Type:</label>
              <select
                value={wartPathType}
                onChange={(e) => setWartPathType(e.target.value)}
              >
                <option value="hardened">Hardened (m/44'/2070'/0'/0/0)</option>
                <option value="non-hardened">Non-Hardened (m/44'/2070'/0/0/0)</option>
              </select>
            </div>
          )}
          <button onClick={handleWartAction}>
            {wartAction === 'create'
              ? 'Create Wallet'
              : wartAction === 'derive'
              ? 'Derive Wallet'
              : wartAction === 'import'
              ? 'Import Wallet'
              : 'Login'}
          </button>
        </section>
      )}

      <section>
        <h3>Validate Address</h3>
        <div className="form-group">
          <label>Address:</label>
          <input
            type="text"
            value={wartAddress}
            onChange={(e) => setWartAddress(e.target.value.trim())}
            placeholder="Enter 48-character address"
          />
        </div>
        <button onClick={handleValidateWartAddress}>Validate Address</button>
        {wartValidateResult && (
          <div className="result">
            <pre>{JSON.stringify(wartValidateResult, null, 2)}</pre>
          </div>
        )}
      </section>

      {wartIsLoggedIn && (
        <section>
          <h3>Send Transaction</h3>
          <div className="form-group">
            <label>To Address:</label>
            <input
              type="text"
              value={wartToAddr}
              onChange={(e) => setWartToAddr(e.target.value.trim())}
              placeholder="Enter 48-character to address"
            />
          </div>
          <div className="form-group">
            <label>Amount (WART):</label>
            <input
              type="text"
              value={wartAmount}
              onChange={(e) => setWartAmount(e.target.value.trim())}
              placeholder="Enter amount in WART (e.g., 1)"
            />
          </div>
          <div className="form-group">
            <label>Fee (WART):</label>
            <input
              type="text"
              value={wartFee}
              onChange={(e) => setWartFee(e.target.value.trim())}
              placeholder="Enter fee in WART (e.g., 0.01)"
            />
          </div>
          <button onClick={handleSendWartTransaction}>Send Transaction</button>
          {wartSendResult && (
            <div className="result">
              <pre>{JSON.stringify(wartSendResult, null, 2)}</pre>
            </div>
          )}
        </section>
      )}

      {wartIsLoggedIn && (
        <section>
          <h3>Bridge Native WART to Liquid</h3>
          <div className="deposit-box">
            <label>Deposit Amount (WART):</label>
            <input
              type="number"
              placeholder="Amount"
              value={wartAmount}
              onChange={(e) => setWartAmount(e.target.value)}
            />
            <button onClick={depositNativeWart} className="btn primary small" disabled={loading}>Deposit to Bridge</button>
          </div>
          <div className="relay-box">
            <label>Relay Deposit Proof (Tx Hash):</label>
            <input
              type="text"
              placeholder="Warthog Tx Hash"
              value={wartTxHashForRelay}
              onChange={(e) => setWartTxHashForRelay(e.target.value)}
            />
            <button onClick={relayWartDepositProof} className="btn primary small" disabled={loading}>Relay to Cartesi</button>
          </div>
        </section>
      )}

      {wartError && (
        <div className="error">
          <strong>Error:</strong> {wartError}
        </div>
      )}

      {/* SubWallet Component Integration */}
      {wartIsLoggedIn && (
        <SubWallet
          mainWallet={wartWallet}
          mainMnemonic={wartWallet?.mnemonic || ''} // Use from wallet if available
          selectedNode={wartSelectedNode}
          fetchBalanceAndNonce={fetchWartBalanceAndNonce}
          sendTransaction={handleSendWartTransaction}
          send={send} // Cartesi send for proofs
          address={address} // L1 address
          loading={loading}
          setLoading={setLoading}
          subWallets={subWallets}
          setSubWallets={setSubWallets}
          subIndex={subIndex}
          setSubIndex={setSubIndex}
          subDepositAmt={subDepositAmt}
          setSubDepositAmt={setSubDepositAmt}
          selectedSub={selectedSub}
          setSelectedSub={setSelectedSub}
          voucherPayload={voucherPayload}
          setVoucherPayload={setVoucherPayload}
          setWartToAddr={setWartToAddr}
          setWartAmount={setWartAmount}
          setWartFee={setWartFee}
          getWartTxProof={getWartTxProof}
        />
      )}

      {wartShowModal && wartWalletData && (
        <div className="modal-overlay">
          <div className="modal-content">
            <h2>Wallet Information</h2>
            <p className="warning">
              Warning: Please write down your seed phrase (if available) and private key on a piece of paper and store them securely. Do not share them with anyone.
            </p>
            <p>Options for securing your wallet:</p>
            <ul>
              <li>Save the wallet to localStorage (encrypted with your password). This allows easy access but is tied to this browser.</li>
              <li>Download the wallet as an encrypted file (warthog_wallet.txt). You can store this file securely and upload it later to login.</li>
            </ul>
            {wartWalletData.wordCount && (
              <p>
                <strong>Word Count:</strong> {wartWalletData.wordCount}
              </p>
            )}
            {wartWalletData.mnemonic && (
              <div>
                <strong>Seed Phrase:</strong>
              <p>
                 <span>{wartWalletData.mnemonic}</span>
              </p>
              </div>
            )}
           
            {wartWalletData.pathType && (
              <p>
                <strong>Path Type:</strong> {wartWalletData.pathType}
              </p>
            )}
            <p>
              <strong>Private Key:</strong><br /><span className="wallet-info-value">{wartWalletData.privateKey}</span>
            </p>
            <p>
              <strong>Public Key:</strong><br /><span className="wallet-info-value">{wartWalletData.publicKey}</span>
            </p>
            <p>
              <strong>Address:</strong><br /> <span className="wallet-info-value">{wartWalletData.address}</span>
            </p>
            <div className="form-group">
              <label>Password to Encrypt Wallet:</label>
              <input
                type="password"
                value={wartPassword}
                onChange={(e) => setWartPassword(e.target.value)}
                placeholder="Enter password to encrypt wallet"
              />
            </div>
            {wartError && (
              <div className="error">
                <strong>Error:</strong> {wartError}
              </div>
            )}
            <div className="form-group">
              <label className="checkbox">
                <input
                  type="checkbox"
                  checked={wartSaveConsent}
                  onChange={(e) => setWartSaveConsent(e.target.checked)}
                />
                Save wallet to localStorage (encrypted)
              </label>
            </div>
            <div>
              <button
                onClick={() => {
                  if (!wartPassword) {
                    setWartError('Please provide a password to encrypt and save the wallet.');
                    return;
                  }
                  if (!wartSaveConsent) {
                    setWartError('Please consent to save the wallet.');
                    return;
                  }
                  setWartError(null);
                  saveWartWallet(wartWalletData);
                  setWartShowModal(false);
                  setWartWalletData(null);
                }}
              >
                Save Wallet
              </button>
              <button
                onClick={() => {
                  if (!wartPassword) {
                    setWartError('Please provide a password to encrypt and download the wallet file.');
                    return;
                  }
                  setWartError(null);
                  downloadWartWallet(wartWalletData);
                  setWartShowModal(false);
                  setWartWalletData(null);
                }}
              >
                Download Wallet File
              </button>
            </div>
            <div>
              <label className="checkbox">
                <input
                  type="checkbox"
                  checked={wartConsentToClose}
                  onChange={(e) => setWartConsentToClose(e.target.checked)}
                />
                I consent to close without saving to local storage or downloading the wallet file
              </label>
              <button className="danger"
                disabled={!wartConsentToClose}
                onClick={() => {
                  setWartShowModal(false);
                  setWartWalletData(null);
                  setWartPassword('');
                  setWartSaveConsent(false);
                  setWartConsentToClose(false);
                  setWartError(null);
                }}
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default WarthogWallet; // Added export default