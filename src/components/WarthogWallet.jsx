// src/components/WarthogWallet.jsx
import React, { useState, useEffect } from 'react';
import CryptoJS from 'crypto-js';
import axios from 'axios';
import { ethers as ethersV6 } from 'ethers-v6';
import TransactionHistory from './TransactionHistory';
import SubWallet from './SubWallet'; // New import for sub-wallet component
import '../styles/warthog.css';

const API_URL = '/api/proxy';

const defaultNodeList = [
  'http://217.182.64.43:3001',
  'http://65.87.7.86:3001',
  'https://warthognode.duckdns.org',
];

const WarthogWallet = ({ send, address: propAddress, l1Address, loading: propLoading, setLoading: propSetLoading }) => {
  const [deferredPrompt, setDeferredPrompt] = useState(null);
  const [walletData, setWalletData] = useState(null);
  const [showModal, setShowModal] = useState(false);
  const [consentToClose, setConsentToClose] = useState(false);
  const [validateResult, setValidateResult] = useState(null);
  const [sendResult, setSendResult] = useState(null);
  const [wallet, setWallet] = useState(null);
  const [balance, setBalance] = useState(null);
  const [nextNonce, setNextNonce] = useState(null); // Renamed for clarity, like wallet.jsx
  const [pinHeight, setPinHeight] = useState(null);
  const [pinHash, setPinHash] = useState(null);
  const [mnemonic, setMnemonic] = useState('');
  const [privateKeyInput, setPrivateKeyInput] = useState('');
  const [validateAddr, setValidateAddr] = useState('');
  const [toAddr, setToAddr] = useState('');
  const [amount, setAmount] = useState('');
  const [fee, setFee] = useState('');
  const [nonceInput, setNonceInput] = useState(''); // New: for manual nonce input
  const [wordCount, setWordCount] = useState('12');
  const [pathType, setPathType] = useState('hardened');
  const [walletAction, setWalletAction] = useState('create');
  const [error, setError] = useState(null);
  const [password, setPassword] = useState('');
  const [saveWalletConsent, setSaveWalletConsent] = useState(false);
  const [showPasswordPrompt, setShowPasswordPrompt] = useState(false);
  const [uploadedFile, setUploadedFile] = useState(null);
  const [isWalletProcessed, setIsWalletProcessed] = useState(false);
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [selectedNode, setSelectedNode] = useState(defaultNodeList[0]);
  const [showDownloadPrompt, setShowDownloadPrompt] = useState(false);
  const [sending, setSending] = useState(false); // New: to disable button during send
  const [failedTransactions, setFailedTransactions] = useState([]); // New: to log failed transactions
  const [sentTransactions, setSentTransactions] = useState([]);
  const [copiedTxId, setCopiedTxId] = useState(null); // New: to track copied Tx ID for feedback
  const [copiedToAddr, setCopiedToAddr] = useState(null); // New: to track copied To Address for feedback
  const [copiedFromAddr, setCopiedFromAddr] = useState(null); // New: to track copied From Address for feedback
  const [isSmallScreen767, setIsSmallScreen767] = useState(false);
  // Sub-wallet states
  const [subWallets, setSubWallets] = useState(() => {
    const saved = localStorage.getItem('warthogSubWallets');
    if (!saved) return [];
    try {
      const bytes = CryptoJS.AES.decrypt(saved, 'your-encryption-key-or-password');
      const decrypted = bytes.toString(CryptoJS.enc.Utf8);
      if (!decrypted) return [];
      return JSON.parse(decrypted);
    } catch (err) {
      console.error('Failed to decrypt/parse subWallets:', err);
      return [];
    }
  });
  const [subIndex, setSubIndex] = useState(0);
  const [subDepositAmt, setSubDepositAmt] = useState('');
  const [selectedSub, setSelectedSub] = useState(null);
  const [voucherPayload, setVoucherPayload] = useState('');

  useEffect(() => {
    localStorage.removeItem('warthogSubWallets');
  }, []);

  useEffect(() => {
    const handleBeforeInstallPrompt = (e) => {
      e.preventDefault();
      setDeferredPrompt(e);
    };

    window.addEventListener('beforeinstallprompt', handleBeforeInstallPrompt);

    return () => {
      window.removeEventListener('beforeinstallprompt', handleBeforeInstallPrompt);
    };
  }, []);

  // Handle app installed event
  useEffect(() => {
    const handleAppInstalled = () => {
      setDeferredPrompt(null);
    };

    window.addEventListener('appinstalled', handleAppInstalled);

    return () => {
      window.removeEventListener('appinstalled', handleAppInstalled);
    };
  }, []);

  useEffect(() => {
    const encryptedWallet = localStorage.getItem('warthogWallet');
    if (encryptedWallet) {
      setShowPasswordPrompt(true);
    }
  }, []);

  useEffect(() => {
    if (wallet?.address) {
      console.log('Fetching balance for address:', wallet.address);
      fetchBalanceAndNonce(wallet.address);
    }
  }, [wallet, selectedNode]);

  useEffect(() => {
    if (showModal) {
      window.alert("If you haven't backed up the information elsewhere, do not close the next window without saving or downloading your private key.");
    }
  }, [showModal]);

  // Poll for pending tx status every 30 seconds if there are pending txs
  useEffect(() => {
    if (sentTransactions.length > 0 && wallet?.address) {
      const interval = setInterval(() => {
        updateTxStatuses();
      }, 30000); // 30 seconds
      return () => clearInterval(interval);
    }
  }, [sentTransactions, wallet, selectedNode]);

  useEffect(() => {
    const handleResize = () => {
      setIsSmallScreen767(window.innerWidth < 767);
    };

    handleResize(); // Set initial value on mount

    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, []);

  // Add effect to persist subWallets (optional but recommended)
  useEffect(() => {
    localStorage.setItem('warthogSubWallets', JSON.stringify(subWallets));
  }, [subWallets]);

  const wartToE8 = (wart) => {
    try {
      const num = parseFloat(wart);
      if (isNaN(num) || num <= 0) return null;
      return Math.round(num * 100000000);
    } catch {
      return null;
    }
  };

  const fetchBalanceAndNonce = async (address, isForSub = false) => {
    setError(null);
    if (!isForSub) {
      setBalance(null);
      setNextNonce(null);
    }
    setPinHeight(null);
    setPinHash(null);

    try {
      const nodeBaseParam = `nodeBase=${encodeURIComponent(selectedNode)}`;
      console.log('Sending chain head request to:', `${API_URL}?nodePath=chain/head&${nodeBaseParam}`);
      const chainHeadResponse = await axios.get(`${API_URL}?nodePath=chain/head&${nodeBaseParam}`, {
        headers: { 'Content-Type': 'application/json' },
      });
      console.log('Chain head response status:', chainHeadResponse.status);
      const chainHeadData = chainHeadResponse.data.data || chainHeadResponse.data;
      console.log('Chain head response data:', chainHeadData);

      setPinHeight(chainHeadData.pinHeight);
      setPinHash(chainHeadData.pinHash);

      console.log('Sending balance request to:', `${API_URL}?nodePath=account/${address}/balance&${nodeBaseParam}`);
      const balanceResponse = await axios.get(`${API_URL}?nodePath=account/${address}/balance&${nodeBaseParam}`, {
        headers: { 'Content-Type': 'application/json' },
      });
      console.log('Balance response status:', balanceResponse.status);
      const balanceData = balanceResponse.data.data || balanceResponse.data;
      console.log('Balance response data:', balanceData);

      const balanceInWart = balanceData.balanceE8 !== undefined ? (balanceData.balanceE8 / 100000000).toFixed(8) : '0';

      const fetchedNonce = Number(balanceData.nonceId) || 0;
      const newNextNonce = Math.max(nextNonce || 0, fetchedNonce + 1);

      if (!isForSub) {
        setBalance(balanceInWart);
        setNextNonce(newNextNonce);
        if (wallet?.address) {
          localStorage.setItem(`warthogNextNonce_${wallet.address}`, newNextNonce);
        }
      }

      console.log('Chain head data:', chainHeadData);
      return { balance: balanceInWart, nextNonce: newNextNonce, pinHeight: chainHeadData.pinHeight, pinHash: chainHeadData.pinHash };
    } catch (err) {
      const errorMessage =
        err.response?.data?.message ||
        err.message ||
        'Could not fetch chain head or balance';
      setError(errorMessage);
      console.error('Fetch error:', err);
      return { balance: '0', nextNonce: 0, pinHeight: null, pinHash: null };
    }
  };

  const updateTxStatuses = async () => {
    const nodeBaseParam = `nodeBase=${encodeURIComponent(selectedNode)}`;
    const updatedTxs = await Promise.all(
      sentTransactions.map(async (tx) => {
        if (tx.status === 'confirmed') return tx;
        try {
          const response = await axios.get(`${API_URL}?nodePath=transaction/lookup/${tx.txHash}&${nodeBaseParam}`);
          const data = response.data.data?.transaction || response.data.data || response.data;
          if (data.blockHeight !== undefined && data.confirmations > 0) {
            return { ...tx, status: 'confirmed', confirmations: data.confirmations };
          }
          return tx;
        } catch {
          return tx;
        }
      })
    );
    setSentTransactions(updatedTxs);
  };

  const encryptWallet = (walletData, password) => {
    const { privateKey, publicKey, address } = walletData;
    const walletToSave = { privateKey, publicKey, address };
    const encrypted = CryptoJS.AES.encrypt(JSON.stringify(walletToSave), password).toString();
    return encrypted;
  };

  const decryptWallet = (encrypted, password) => {
    try {
      const bytes = CryptoJS.AES.decrypt(encrypted, password);
      const decrypted = bytes.toString(CryptoJS.enc.Utf8);
      if (!decrypted) throw new Error('Invalid password');
      return JSON.parse(decrypted);
    } catch {
      throw new Error('Failed to decrypt wallet: Invalid password');
    }
  };

  const saveWallet = (walletData) => {
    if (!saveWalletConsent || !password) {
      setError('Please provide a password and consent to save the wallet');
      return false;
    }
    try {
      const encrypted = encryptWallet(walletData, password);
      localStorage.setItem('warthogWallet', encrypted);
      setWallet(walletData);
      setShowPasswordPrompt(false);
      setError(null);
      setIsWalletProcessed(true);
      setPassword('');
      setSaveWalletConsent(false);
      setIsLoggedIn(true);
      return true;
    } catch (err) {
      setError(err.message);
      return false;
    }
  };

  const downloadWallet = (walletData) => {
    if (!password) {
      setError('Please provide a password to encrypt the wallet file');
      return;
    }
    const encrypted = encryptWallet(walletData, password);
    const blob = new Blob([encrypted], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'warthog_wallet.txt';
    a.click();
    URL.revokeObjectURL(url);
    setIsWalletProcessed(true);
    setPassword('');
    setSaveWalletConsent(false);
  };

  const handleFileUpload = (event) => {
    const file = event.target.files[0];
    if (!file) {
      setError('No file selected');
      return;
    }
    const reader = new FileReader();
    reader.onload = (e) => {
      setUploadedFile(e.target.result);
    };
    reader.onerror = () => setError('Failed to read file');
    reader.readAsText(file);
  };

  const loadWallet = () => {
    if (!password) {
      setError('Please provide a password');
      return;
    }
    try {
      let encrypted;
      if (uploadedFile) {
        encrypted = uploadedFile;
      } else {
        encrypted = localStorage.getItem('warthogWallet');
        if (!encrypted) throw new Error('No wallet found in storage or file');
      }
      const decryptedWallet = decryptWallet(encrypted, password);
      setWallet(decryptedWallet);
      const storedNonce = localStorage.getItem(`warthogNextNonce_${decryptedWallet.address}`);
      if (storedNonce) {
        setNextNonce(Number(storedNonce));
      }
      setShowPasswordPrompt(false);
      setUploadedFile(null);
      setError(null);
      setIsWalletProcessed(false);
      setIsLoggedIn(true);
    } catch (err) {
      setError(err.message);
    }
  };

  const clearWallet = () => {
    localStorage.removeItem('warthogWallet');
    if (wallet?.address) {
      localStorage.removeItem(`warthogNextNonce_${wallet.address}`);
    }
    setWallet(null);
    setBalance(null);
    setNextNonce(null);
    setPinHeight(null);
    setPinHash(null);
    setError(null);
    setPassword('');
    setSaveWalletConsent(false);
    setUploadedFile(null);
    setIsWalletProcessed(false);
    setIsLoggedIn(false);
    setFailedTransactions([]); // Clear failed logs on wallet clear
    setSentTransactions([]); // Clear sent logs on wallet clear
    setNonceInput('');
  };

  const generateWallet = async (wordCount, pathType) => {
    const strengthBytes = wordCount === 12 ? 16 : 32;
    const entropy = window.crypto.getRandomValues(new Uint8Array(strengthBytes));
    const mnemonicObj = ethersV6.Mnemonic.fromEntropy(ethersV6.hexlify(entropy));
    const mnemonic = mnemonicObj.phrase;
    const path = pathType === 'hardened' ? "m/44'/2070'/0'/0/0" : "m/44'/2070'/0/0/0";
    const hdWallet = ethersV6.HDNodeWallet.fromPhrase(mnemonic, '', path);
    const publicKey = hdWallet.publicKey.slice(2);
    const sha = ethersV6.sha256('0x' + publicKey).slice(2);
    const ripemd = ethersV6.ripemd160('0x' + sha).slice(2);
    const checksum = ethersV6.sha256('0x' + ripemd).slice(2, 10);
    const address = ripemd + checksum;
    return {
      mnemonic,
      wordCount,
      pathType,
      privateKey: hdWallet.privateKey.slice(2),
      publicKey,
      address,
    };
  };

  const deriveWallet = (mnemonic, wordCount, pathType) => {
    try {
      const words = mnemonic.trim().split(/\s+/);
      const expectedWordCount = Number(wordCount);
      if (words.length !== expectedWordCount) {
        throw new Error(`Invalid mnemonic: must have exactly ${expectedWordCount} words`);
      }
      const path = pathType === 'hardened' ? "m/44'/2070'/0'/0/0" : "m/44'/2070'/0/0/0";
      const hdWallet = ethersV6.HDNodeWallet.fromPhrase(mnemonic, '', path);
      const publicKey = hdWallet.publicKey.slice(2);
      const sha = ethersV6.sha256('0x' + publicKey).slice(2);
      const ripemd = ethersV6.ripemd160('0x' + sha).slice(2);
      const checksum = ethersV6.sha256('0x' + ripemd).slice(2, 10);
      const address = ripemd + checksum;
      return {
        mnemonic,
        wordCount,
        pathType,
        privateKey: hdWallet.privateKey.slice(2),
        publicKey,
        address,
      };
    } catch (err) {
      throw new Error('Invalid mnemonic');
    }
  };

  const importFromPrivateKey = (privKey) => {
    console.log('Input length:', privKey.length);  // Should be 64
    console.log('Is hex:', /^[0-9a-fA-F]+$/.test(privKey));  // Should be true
    try {
      if (privKey.length !== 64) {
        throw new Error('Private key must be exactly 64 characters long');
      }
      if (!/^[0-9a-fA-F]+$/.test(privKey)) {
        throw new Error('Private key must consist of hexadecimal characters only (0-9, a-f, A-F)');
      }
      const signer = new ethersV6.Wallet('0x' + privKey);
      const publicKey = signer.signingKey.compressedPublicKey.slice(2);
      const sha = ethersV6.sha256('0x' + publicKey).slice(2);
      const ripemd = ethersV6.ripemd160('0x' + sha).slice(2);
      const checksum = ethersV6.sha256('0x' + ripemd).slice(2, 10);
      const address = ripemd + checksum;
      console.log('Derived address:', address);  // For extra verification
      return {
        privateKey: privKey,
        publicKey,
        address,
      };
    } catch (err) {
      console.error('Validation error:', err.message);
      throw new Error(err.message || 'Invalid private key');
    }
  };

  const handleWalletAction = async () => {
    setError(null);
    setIsWalletProcessed(false);

    if (walletAction === 'login' && !uploadedFile) {
      setError('Please upload the warthog_wallet.txt file');
      return;
    }

    if (walletAction === 'login') {
      loadWallet();
      return;
    }

    if (walletAction === 'derive' && !mnemonic) {
      setError('Please enter a seed phrase');
      return;
    }

    if (walletAction === 'import' && !privateKeyInput) {
      setError('Please enter a private key');
      return;
    }

    if (walletAction === 'derive') {
      const words = mnemonic.trim().split(/\s+/);
      const expectedWordCount = Number(wordCount);
      if (words.length !== expectedWordCount) {
        setError(`Seed phrase must have exactly ${expectedWordCount} words`);
        return;
      }
    }

    try {
      let data;
      if (walletAction === 'create') {
        data = await generateWallet(Number(wordCount), pathType);
      } else if (walletAction === 'derive') {
        data = deriveWallet(mnemonic, Number(wordCount), pathType);
      } else if (walletAction === 'import') {
        data = importFromPrivateKey(privateKeyInput);
      }
      setWalletData(data);
      setShowModal(true);
      setConsentToClose(false);
    } catch (err) {
      const errorMessage = err.message || `Failed to ${walletAction} wallet`;
      setError(errorMessage);
      clearWallet();
      console.error(`Wallet action error:`, err);
    }
  };

  const validateAddress = (addr) => {
    if (typeof addr !== 'string' || addr.length !== 48) {
      return { valid: false };
    }
    const ripemdHex = addr.slice(0, 40);
    const checksumHex = addr.slice(40);
    const computedChecksum = ethersV6.sha256('0x' + ripemdHex).slice(2, 10);
    return { valid: computedChecksum === checksumHex };
  };

  const handleValidateAddress = () => {
    setError(null);
    setValidateResult(null);
    if (!validateAddr) {
      setError('Please enter an address');
      return;
    }
    try {
      const result = validateAddress(validateAddr);
      setValidateResult(result);
    } catch (err) {
      const errorMessage = err.message || 'Failed to validate address';
      setError(errorMessage);
      console.error('Validate error:', err);
    }
  };

  const getRoundedFeeE8 = async (feeWart) => {
    const nodeBaseParam = `nodeBase=${encodeURIComponent(selectedNode)}`;
    try {
      const response = await axios.get(`${API_URL}?nodePath=tools/encode16bit/from_string/${feeWart}&${nodeBaseParam}`);
      const feeData = response.data.data || response.data;
      return feeData.roundedE8;
    } catch (err) {
      throw new Error('Failed to round fee');
    }
  };

  const handleSendTransaction = async (fromPrivKey = wallet?.privateKey, fromAddress = wallet?.address, to = toAddr, amountVal = amount, feeVal = fee) => {
    if (sending) return; // Prevent multiple sends
    setSending(true);
    setError(null);
    setSendResult(null);
    if (!to || !amountVal || !feeVal) {
      setError('Please fill in all transaction fields');
      setSending(false);
      return;
    }
    const amountNum = parseFloat(amountVal);
    const feeNum = parseFloat(feeVal);
    if (isNaN(amountNum) || amountNum <= 0 || isNaN(feeNum) || feeNum <= 0) {
      setError('Invalid amount or fee: must be positive numbers');
      setSending(false);
      return;
    }
    const amountE8 = wartToE8(amountVal);
    let feeE8;
    try {
      feeE8 = await getRoundedFeeE8(feeVal);
    } catch {
      setError('Invalid fee or failed to round');
      setSending(false);
      return;
    }
    if (!amountE8 || !feeE8) {
      setError('Invalid amount or fee');
      setSending(false);
      return;
    }
    if (!fromPrivKey) {
      setError('No private key available.');
      setSending(false);
      return;
    }
    const isForSub = fromAddress !== wallet?.address;
    if (nextNonce === null || pinHeight === null || pinHash === null) {
      setError('Nonce or chain head not available. Fetching latest...');
      await fetchBalanceAndNonce(fromAddress, isForSub); // Fetch fresh if missing
    }
    if (nextNonce === null || pinHeight === null || pinHash === null) {
      setError('Failed to fetch nonce or chain head. Please try again.');
      setSending(false);
      return;
    }

    let txNonce = nextNonce;
    if (nonceInput !== '') {
      const parsedNonce = Number(nonceInput);
      if (isNaN(parsedNonce) || parsedNonce < 0 || !Number.isInteger(parsedNonce)) {
        setError('Invalid nonce: must be a non-negative integer');
        setSending(false);
        return;
      }
      txNonce = parsedNonce;
    }

    // Capture transaction details for logging if failed
    const txDetails = {
      toAddr: to,
      amount: amountVal,
      fee: feeVal,
      nonce: txNonce,
      timestamp: new Date().toISOString(),
    };

    // NEW: Faux MetaMask confirmation with tx details
    if (window.ethereum) {
      try {
        const accounts = await window.ethereum.request({ method: 'eth_accounts' });
        if (accounts.length === 0) {
          throw new Error('No MetaMask account connected. Please connect your wallet.');
        }
        const signerAddress = accounts[0];  // Use connected L1 address for faux sign

        const txSummaryMessage = `Confirm Warthog Transaction:\nFrom: ${fromAddress}\nTo: ${to}\nAmount: ${amountVal} WART\nFee: ${feeVal} WART\nNonce: ${txNonce}\n\nThis is a confirmation step—approve to proceed.`;

        // Trigger MetaMask popup with readable details
        await window.ethereum.request({
          method: 'personal_sign',
          params: [txSummaryMessage, signerAddress],
        });
        // If here, user confirmed—proceed with actual software signing
      } catch (err) {
        setError(`MetaMask confirmation failed: ${err.message}. Transaction canceled.`);
        setSending(false);
        return;  // Exit without sending
      }
    } else {
      // No MetaMask: Skip faux confirmation (or prompt for installation)
      console.warn('MetaMask not detected—proceeding without confirmation.');
    }

    // Proceed with WORKING tx building and software signing
    try {
      const pinHashBytes = ethersV6.getBytes('0x' + pinHash);
      const heightBytes = new Uint8Array(4);
      new DataView(heightBytes.buffer).setUint32(0, pinHeight, false);
      const nonceBytes = new Uint8Array(4);
      new DataView(nonceBytes.buffer).setUint32(0, txNonce, false);
      const reserved = new Uint8Array(3);
      const feeBytes = new Uint8Array(8);
      new DataView(feeBytes.buffer).setBigUint64(0, BigInt(feeE8), false);
      const toRawBytes = ethersV6.getBytes('0x' + to.slice(0, 40));
      const amountBytes = new Uint8Array(8);
      new DataView(amountBytes.buffer).setBigUint64(0, BigInt(amountE8), false);

      const messageBytes = ethersV6.concat([
        pinHashBytes,
        heightBytes,
        nonceBytes,
        reserved,
        feeBytes,
        toRawBytes,
        amountBytes,
      ]);

      const txHash = ethersV6.sha256(messageBytes);
      const txHashBytes = ethersV6.getBytes(txHash);

      const signer = new ethersV6.Wallet('0x' + fromPrivKey);
      const sig = signer.signingKey.sign(txHashBytes);

      const rHex = sig.r.slice(2);
      const sHex = sig.s.slice(2);
      const recid = sig.v - 27;
      const recidHex = recid.toString(16).padStart(2, '0');
      const signature65 = rHex + sHex + recidHex;

      const nodeBaseParam = `nodeBase=${encodeURIComponent(selectedNode)}`;
      console.log('Sending transaction request to:', `${API_URL}?nodePath=transaction/add&${nodeBaseParam}`);
      const response = await axios.post(
        `${API_URL}?nodePath=transaction/add&${nodeBaseParam}`,
        {
          pinHeight,
          nonceId: txNonce,
          toAddr: to,
          amountE8,
          feeE8,
          signature65,
        },
        { headers: { 'Content-Type': 'application/json' } }
      );
      console.log('Send transaction response status:', response.status);
      const data = response.data;
      console.log('Send transaction response data:', data);

      // Check for error in response data
      if (data.error || (data.code && data.code !== 0)) {
        throw new Error(data.error || `Transaction error code: ${data.code}`);
      }

      setSendResult(data);

      // Optimistic updates on success
      const newNextNonce = Math.max(nextNonce || 0, txNonce + 1);
      setNextNonce(newNextNonce);
      if (wallet?.address && !isForSub) {
        localStorage.setItem(`warthogNextNonce_${wallet.address}`, newNextNonce);
      }
      if (!isForSub) {
        setBalance((parseFloat(balance) - amountNum - feeNum).toFixed(8));
      }

      // Log successful sent transaction as pending (only for main wallet)
      if (!isForSub) {
        setSentTransactions((prev) => [
          ...prev,
          { ...txDetails, txHash: data.data?.txHash || data.txHash, status: 'pending' }, // Adjust based on response structure
        ]);
      }

      // Clear input fields on success if sending from main
      if (!isForSub) {
        setToAddr('');
        setAmount('');
        setFee('');
        setNonceInput('');
      }

      return data; // Return response for sub-deposit use (e.g., txHash capture)
    } catch (err) {
      const errorMessage = err.response?.data?.message || err.message || 'Failed to send transaction';
      setError(errorMessage);
      console.error('Fetch send transaction error:', err);

      // Log the failed transaction (only for main wallet)
      if (!isForSub) {
        setFailedTransactions((prev) => [
          ...prev,
          { ...txDetails, error: errorMessage },
        ]);
      }

      return null; // Return null on error for callers
    } finally {
      setSending(false);
    }
  };
  // Add this function (placeholder; implement real proof fetching as needed)
  const getWartTxProof = async (txHash) => {
    propSetLoading(true);
    try {
      const nodeBaseParam = `nodeBase=${encodeURIComponent(selectedNode)}`;
      console.log('Fetching Warthog TX proof from:', `${API_URL}?nodePath=transaction/lookup/${txHash}&${nodeBaseParam}`);
      const response = await axios.get(`${API_URL}?nodePath=transaction/lookup/${txHash}&${nodeBaseParam}`, {
        headers: { 'Content-Type': 'application/json' },
      });
      console.log('TX proof response status:', response.status);
      const data = response.data.data || response.data;
      console.log('TX proof data:', data);
      // Assuming the full TX data serves as the "proof" for backend validation (e.g., { blockHash, txIndex, from, to, amount, ... })
      return data;
    } catch (err) {
      const errorMessage = err.response?.data?.message || err.message || 'Failed to fetch Warthog TX proof';
      setError(errorMessage);
      console.error('TX proof error:', err);
      throw new Error(errorMessage);
    } finally {
      propSetLoading(false);
    }
  };

  const handleInstallClick = async () => {
    if (deferredPrompt) {
      deferredPrompt.prompt();
      const { outcome } = await deferredPrompt.userChoice;
      if (outcome === 'accepted') {
        console.log('User accepted the install prompt');
      } else {
        console.log('User dismissed the install prompt');
      }
      setDeferredPrompt(null);
    }
  };

  const copyToClipboard = (text, setter) => {
    navigator.clipboard.writeText(text).then(() => {
      setter(text); // Set to show "Copied!" feedback
      setTimeout(() => setter(null), 2000); // Reset after 2s
    }).catch(err => {
      console.error('Failed to copy: ', err);
    });
  };

  return (
    <div className="warthog-section">
      <h1>Warthog Wallet</h1>
      {deferredPrompt && (
        <button onClick={handleInstallClick} style={{ marginBottom: '20px', padding: '8px 16px', backgroundColor: '#4CAF50', color: 'white', border: 'none', borderRadius: '4px', cursor: 'pointer' }}>
          Install Wallet App
        </button>
      )}
      {!showModal && (
        <>
          <section>
            <h2>Node Selection</h2>
            <div className="form-group">
              <label>Select Node:</label>
              <select
                value={selectedNode}
                onChange={(e) => setSelectedNode(e.target.value)}
                className="input"
              >
                {defaultNodeList.map((node, index) => (
                  <option key={index} value={node}>
                    {node}
                  </option>
                ))}
              </select>
            </div>
          </section>

          {showPasswordPrompt && !wallet && (
            <section>
              <h2>Unlock Wallet</h2>
              <div className="form-group">
                <label>Upload Wallet File (optional):</label>
                <input type="file" accept=".txt" onChange={handleFileUpload} className="input" />
              </div>
              <div className="form-group">
                <label>Password:</label>
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Enter password to unlock wallet"
                  className="input"
                />
              </div>
              <button onClick={loadWallet}>Unlock Wallet</button>
              <button
                onClick={() => {
                  setShowPasswordPrompt(false);
                  setPassword('');
                  setUploadedFile(null);
                }}
              >
                Cancel
              </button>
            </section>
          )}

          {wallet && (
            <section>
              <div style={{display: 'flex', justifyContent: 'space-between', alignItems: 'center'}}>
                <h2>Wallet</h2>
                <button
                  className="download-wallet-btn"
                  onClick={() => setShowDownloadPrompt(true)}
                >
                  Download Wallet File
                </button>
              </div>
              <p className="wallet-address">
                <strong>Address:</strong> {wallet.address}
              </p>
              <p>
                <strong>Balance:</strong>{' '}
                {balance !== null ? `${balance} WART` : 'Loading...'}
              </p>
              <button onClick={() => fetchBalanceAndNonce(wallet.address)}>
                Refresh Balance
              </button>
              <button onClick={clearWallet}>Clear Wallet</button>
              <p className="warning">
                Warning: Private key is encrypted in localStorage. Keep your password secure.
              </p>
              <TransactionHistory address={wallet.address} node={selectedNode} />
            </section>
          )}

          {showDownloadPrompt && (
            <div className="modal-overlay">
              <div className="modal-content">
                <h2>Download Wallet File</h2>
                <div className="form-group">
                  <label>Password to Encrypt Wallet:</label>
                  <input
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="Enter password to encrypt wallet"
                    className="input"
                  />
                </div>
                <button onClick={() => { downloadWallet(wallet); setShowDownloadPrompt(false); }}>
                  Download
                </button>
                <button onClick={() => { setShowDownloadPrompt(false); setPassword(''); }}>
                  Cancel
                </button>
              </div>
            </div>
          )}

          {!isLoggedIn && (
            <section>
              <h2>Wallet Management</h2>
              <div className="form-group">
                <label>Action:</label>
                <select
                  value={walletAction}
                  onChange={(e) => {
                    setWalletAction(e.target.value);
                    setError(null);
                    setMnemonic('');
                    setPrivateKeyInput('');
                    setUploadedFile(null);
                    setPassword('');
                    setIsWalletProcessed(false);
                  }}
                  className="input"
                >
                  <option value="create">Create New Wallet</option>
                  <option value="derive">Derive Wallet from Seed Phrase</option>
                  <option value="import">Import from Private Key</option>
                  <option value="login">Login with Wallet File</option>
                </select>
              </div>
              {walletAction === 'derive' && (
                <div className="form-group">
                  <label>Seed Phrase:</label>
                  <input
                    type="text"
                    value={mnemonic}
                    onChange={(e) => setMnemonic(e.target.value)}
                    placeholder="Enter 12 or 24-word seed phrase"
                    className="input"
                  />
                </div>
              )}
              {walletAction === 'import' && (
                <div className="form-group">
                  <label>Private Key:</label>
                  <input
                    type="text"
                    value={privateKeyInput}
                    onChange={(e) => setPrivateKeyInput(e.target.value.replace(/\s/g, ''))}
                    placeholder="Enter 64-character hex private key"
                    className="input"
                  />
                </div>
              )}
              {walletAction === 'login' && (
                <>
                  <div className="form-group">
                    <label>Upload Wallet File (warthog_wallet.txt):</label>
                    <input
                      type="file"
                      accept=".txt"
                      onChange={handleFileUpload}
                      className="input"
                    />
                  </div>
                  <div className="form-group">
                    <label>Password:</label>
                    <input
                      type="password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      placeholder="Enter password to decrypt wallet"
                      className="input"
                    />
                  </div>
                </>
              )}
              {(walletAction === 'create' || walletAction === 'derive') && (
                <div className="form-group">
                  <label>Word Count:</label>
                  <select
                    value={wordCount}
                    onChange={(e) => setWordCount(e.target.value)}
                    className="input"
                  >
                    <option value="12">12 Words</option>
                    <option value="24">24 Words</option>
                  </select>
                </div>
              )}
              {(walletAction === 'create' || walletAction === 'derive') && wordCount === '12' && (
                <div className="form-group">
                  <label>Derivation Path Type:</label>
                  <select
                    value={pathType}
                    onChange={(e) => setPathType(e.target.value)}
                    className="input"
                  >
                    <option value="hardened">Hardened (m/44'/2070'/0'/0/0)</option>
                    <option value="non-hardened">Non-Hardened (m/44'/2070'/0/0/0)</option>
                  </select>
                </div>
              )}
              <button onClick={handleWalletAction}>
                {walletAction === 'create'
                  ? 'Create Wallet'
                  : walletAction === 'derive'
                  ? 'Derive Wallet'
                  : walletAction === 'import'
                  ? 'Import Wallet'
                  : 'Login'}
              </button>
            </section>
          )}

          <section>
            <h2>Validate Address</h2>
            <div className="form-group">
              <label>Address:</label>
              <input
                type="text"
                value={validateAddr}
                onChange={(e) => setValidateAddr(e.target.value.trim())}
                placeholder="Enter 48-character address"
                className="input"
              />
            </div>
            <button onClick={handleValidateAddress}>Validate Address</button>
            {validateResult && (
              <div className="result">
                <pre>{JSON.stringify(validateResult, null, 2)}</pre>
              </div>
            )}
          </section>

          {isLoggedIn && (
            <section>
              <h2>Send Transaction</h2>
              <div className="form-group">
                <label>To Address:</label>
                <input
                  type="text"
                  value={toAddr}
                  onChange={(e) => setToAddr(e.target.value.trim())}
                  placeholder="Enter 48-character to address"
                  className="input"
                />
              </div>
              <div className="form-group">
                <label>Amount (WART):</label>
                <input
                  type="text"
                  value={amount}
                  onChange={(e) => setAmount(e.target.value.trim())}
                  placeholder="Enter amount in WART (e.g., 1)"
                  className="input"
                />
              </div>
              <div className="form-group">
                <label>Fee (WART):</label>
                <input
                  type="text"
                  value={fee}
                  onChange={(e) => setFee(e.target.value.trim())}
                  placeholder="Enter fee in WART (e.g., 0.0001)"
                  className="input"
                />
              </div>
              <div className="form-group">
                <label>Nonce:</label>
                <input
                  type="text"
                  value={nonceInput}
                  onChange={(e) => setNonceInput(e.target.value.trim())}
                  placeholder={`Auto: ${nextNonce || 'Loading'}`}
                  className="input"
                />
              </div>
              <button onClick={() => handleSendTransaction()} disabled={sending}>
                {sending ? 'Sending...' : 'Send Transaction'}
              </button>
              {sendResult && (
                <div className="result">
                  <pre>{JSON.stringify(sendResult, null, 2)}</pre>
                </div>
              )}
            </section>
          )}

          {isLoggedIn && sentTransactions.length > 0 && (
            <section>
              <h2>Sent Transactions Log</h2>
              <button onClick={updateTxStatuses}>Refresh Tx Status</button>
              <ul>
                {sentTransactions.map((tx, index) => (
                  <li key={index} className="tx-log-item">
                    <p><strong>Timestamp:</strong> {tx.timestamp}</p>
                    <p>
                      <strong>From:</strong>{' '}
                      <span
                        className="truncate-text cursor-pointer"
                        title={wallet.address}
                        onClick={() => copyToClipboard(wallet.address, setCopiedFromAddr)}
                      >
                        {isSmallScreen767 ? `${wallet.address.slice(0, 6)}...${wallet.address.slice(-4)}` : wallet.address}
                        {copiedFromAddr === wallet.address ? ' (Copied!)' : ''}
                      </span>
                    </p>
                    <p>
                      <strong>To:</strong>{' '}
                      <span
                        className="truncate-text cursor-pointer"
                        title={tx.toAddr}
                        onClick={() => copyToClipboard(tx.toAddr, setCopiedToAddr)}
                      >
                        {isSmallScreen767 ? `${tx.toAddr.slice(0, 6)}...${tx.toAddr.slice(-4)}` : tx.toAddr}
                        {copiedToAddr === tx.toAddr ? ' (Copied!)' : ''}
                      </span>
                    </p>
                    <p><strong>Amount:</strong> {tx.amount} WART</p>
                    <p><strong>Fee:</strong> {tx.fee} WART</p>
                    <p><strong>Nonce (Session Index):</strong> {tx.nonce}</p>
                    <p>
                      <strong>Tx Hash:</strong>{' '}
                      <span
                        className="truncate-text cursor-pointer"
                        title={tx.txHash}
                        onClick={() => copyToClipboard(tx.txHash, setCopiedTxId)}
                      >
                        {isSmallScreen767 ? `${tx.txHash.slice(0, 6)}...${tx.txHash.slice(-4)}` : tx.txHash}
                        {copiedTxId === tx.txHash ? ' (Copied!)' : ''}
                      </span>
                    </p>
                    <p><strong>Status:</strong> {tx.status} {tx.confirmations ? `(${tx.confirmations} confirmations)` : ''}</p>
                  </li>
                ))}
              </ul>
            </section>
          )}

          {isLoggedIn && failedTransactions.length > 0 && (
            <section>
              <h2>Failed Transactions Log</h2>
              <ul>
                {failedTransactions.map((tx, index) => (
                  <li key={index} className="tx-log-item">
                    <p><strong>Timestamp:</strong> {tx.timestamp}</p>
                    <p>
                      <strong>From:</strong>{' '}
                      <span
                        className="truncate-text cursor-pointer"
                        title={wallet.address}
                        onClick={() => copyToClipboard(wallet.address, setCopiedFromAddr)}
                      >
                        {isSmallScreen767 ? `${wallet.address.slice(0, 6)}...${wallet.address.slice(-4)}` : wallet.address}
                        {copiedFromAddr === wallet.address ? ' (Copied!)' : ''}
                      </span>
                    </p>
                    <p>
                      <strong>To:</strong>{' '}
                      <span
                        className="truncate-text cursor-pointer"
                        title={tx.toAddr}
                        onClick={() => copyToClipboard(tx.toAddr, setCopiedToAddr)}
                      >
                        {isSmallScreen767 ? `${tx.toAddr.slice(0, 6)}...${tx.toAddr.slice(-4)}` : tx.toAddr}
                        {copiedToAddr === tx.toAddr ? ' (Copied!)' : ''}
                      </span>
                    </p>
                    <p><strong>Amount:</strong> {tx.amount} WART</p>
                    <p><strong>Fee:</strong> {tx.fee} WART</p>
                    <p><strong>Nonce:</strong> {tx.nonce}</p>
                    <p><strong>Error:</strong> {tx.error}</p>
                  </li>
                ))}
              </ul>
            </section>
          )}

          {isLoggedIn && wallet.mnemonic && (
            <SubWallet
              mainWallet={wallet} // Pass full wallet object
              mainMnemonic={wallet.mnemonic}
              selectedNode={selectedNode}
              fetchBalanceAndNonce={fetchBalanceAndNonce}
              sendTransaction={handleSendTransaction} // Matches your existing prop
              send={send}
              address={wallet.address} // Fixed name
              l1Address={l1Address} // Pass L1 MetaMask address
              loading={propLoading}
              setLoading={propSetLoading}
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
              setWartToAddr={setToAddr} // Maps to parent's setToAddr
              setWartAmount={setAmount} // Maps to parent's setAmount
              setWartFee={setFee} // Maps to parent's setFee
              getWartTxProof={getWartTxProof} // New function
              sentTransactions={sentTransactions}
            />
          )}

          {error && (
            <div className="error">
              <strong>Error:</strong> {error}
            </div>
          )}
        </>
      )}

      {showModal && walletData && (
        <div className="modal-overlay">
          <div className="modal-content">
            <h2>Wallet Information</h2>
            <p className="warning">
              Warning: Please write down your seed phrase (if available) and private key on a piece of paper and store them securely. Do not share them with anyone.
            </p>
            <p style={{color: '#FFECB3'}}>Options for securing your wallet:</p>
            <ul style={{color: '#FFECB3'}}>
              <li>Save the wallet to localStorage (encrypted with your password). This allows easy access but is tied to this browser.</li>
              <li>Download the wallet as an encrypted file (warthog_wallet.txt). You can store this file securely and upload it later to login.</li>
            </ul>
            {walletData.wordCount && (
              <p style={{padding: '1rem',fontFamily: 'Montserrat'}}>
                <strong>Word Count:</strong> {walletData.wordCount}
              </p>
            )}
            {walletData.mnemonic && (
              <div>
                <strong style={{color: '#e9e6dbff'}}>Seed Phrase:</strong>
                <p style={{backgroundColor: '#ffecb33d', padding: '10px', borderRadius: '5px'}}>
                  <span style={{color: '#caa21eff', fontSize:"large", fontFamily: 'Montserrat', fontWeight: 'bold', textShadow: '1px 1px 1px rgba(0, 0, 0, 0.5)'}}>{walletData.mnemonic}</span>
                </p>
              </div>
            )}

            {walletData.pathType && (
              <p style={{padding: '.75rem'}}>
                <strong>Path Type:</strong> {walletData.pathType}
              </p>
            )}
            <p>
              <strong>Private Key:</strong><br /><span className="wallet-info-value">{walletData.privateKey}</span>
            </p>
            <p>
              <strong>Public Key:</strong><br /><span className="wallet-info-value">{walletData.publicKey}</span>
            </p>
            <p>
              <strong>Address:</strong><br /> <span className="wallet-info-value">{walletData.address}</span>
            </p>
            <div className="form-group" style={{padding: '.75rem'}}>
              <label>Password to Encrypt Wallet:</label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Enter password to encrypt wallet"
                className="input"
              />
            </div>
            {error && (
              <div className="error" style={{marginBottom: '10px'}}>
                <strong>Error:</strong> {error}
              </div>
            )}
            <div className="form-group">
              <label>
                <input
                  type="checkbox"
                  checked={saveWalletConsent}
                  onChange={(e) => setSaveWalletConsent(e.target.checked)}
                />
                Save wallet to localStorage (encrypted)
              </label>
            </div>
            <div style={{marginBottom: '20px'}}>
              <button
                onClick={() => {
                  if (!password) {
                    setError('Please provide a password to encrypt and save the wallet.');
                    return;
                  }
                  if (!saveWalletConsent) {
                    setError('Please consent to save the wallet.');
                    return;
                  }
                  setError(null);
                  saveWallet(walletData);
                  setShowModal(false);
                  setWalletData(null);
                }}
              >
                Save Wallet
              </button>
              <button
                onClick={() => {
                  if (!password) {
                    setError('Please provide a password to encrypt and download the wallet file.');
                    return;
                  }
                  setError(null);
                  downloadWallet(walletData);
                  setShowModal(false);
                  setWalletData(null);
                }}
              >
                Download Wallet File
              </button>
            </div>
            <div style={{display: 'flex', justifyContent: 'flex-end', alignItems: 'center', gap: '10px'}}>
              <label>
                <input
                  type="checkbox"
                  checked={consentToClose}
                  onChange={(e) => setConsentToClose(e.target.checked)}
                />
                I consent to close without saving to local storage or downloading the wallet file
              </label>
              <button
                disabled={!consentToClose}
                onClick={() => {
                  setShowModal(false);
                  setWalletData(null);
                  setPassword('');
                  setSaveWalletConsent(false);
                  setConsentToClose(false);
                  setError(null);
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
};

export default WarthogWallet;
