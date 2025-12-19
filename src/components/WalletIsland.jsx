// src/components/WalletIsland.jsx — MERGED WITH WARTHOG WALLET FOR ASTRO (December 2025)
// Updated with class-based styles for Warthog section

import { useState, useEffect } from 'react';
import { Wallet, Zap, ArrowDown, Coins, RefreshCw } from 'lucide-react';
import { Toaster, toast } from 'react-hot-toast';
import { ethers } from 'ethers';
import CryptoJS from 'crypto-js';
import axios from 'axios';
import '../styles/global.css'; // Assuming global styles (including new Warthog CSS) in Astro

// CARTESI CLI LOCAL CONFIG (from original WalletIsland)
const INSPECT_URL = "/rollup/inspect";  // Proxy to 8080 for vault reads
const RPC_URL = "http://localhost:8545";  // Anvil RPC - update to Sepolia if needed
const INPUT_BOX_ADDRESS = "0x59b22D57D4f067708AB0c00552767405926dc768";
const DAPP_ADDRESS = "0xab7528bb862fB57E8A2BCd567a2e929a0Be56a5e";  // Update if needed

// PORTAL AND TOKEN ADDRESSES (from original)
const ETHER_PORTAL_ADDRESS = "0xFfdbe43d4c855BF7e0f105c400A50857f53AB044";
const ERC20_PORTAL_ADDRESS = "0x4b088b2dee4d3c6ec7aa5fb4e6cd8e9f0a1b2c3d";
const WWART_ADDRESS = "0xYourWWARTContractHere"; // Update
const CTSI_ADDRESS = "0xae7f61eCf06C65405560166b259C54031428A9C4";
const PDAI_ADDRESS = "0xYourPDAIContractHere"; // Update, assumes 6 decimals

// WARTHOG CONFIG (from wallet.jsx)
const API_URL = '/api/proxy'; // Your proxy for Warthog RPC (or adjust for Astro routes if needed)
const defaultNodeList = [
  'https://warthognode.duckdns.org',
  'http://217.182.64.43:3001',
  'http://65.87.7.86:3001',
  // Add more
];
const BRIDGE_ADDRESS = 'YourWarthogBridgeAddressHere'; // Warthog bridge/multisig addr for deposits

const INPUT_BOX_ABI = [
  "function addInput(address dappAddress, bytes calldata input) external returns (uint256)"
];

const ETHER_PORTAL_ABI = [
  "function depositEther(address _dapp, bytes calldata _execLayerData) external payable"
];

const ERC20_PORTAL_ABI = [
  "function depositERC20Tokens(address _erc20, address _dapp, uint256 _amount, bytes calldata _execLayerData) external"
];

const ERC20_ABI = [
  "function approve(address spender, uint256 amount) external returns (bool)",
  "function allowance(address owner, address spender) view returns (uint256)"
];

export default function WalletIsland() {
  // STATES FROM ORIGINAL WalletIsland
  const [address, setAddress] = useState('');
  const [connected, setConnected] = useState(false);
  const [provider, setProvider] = useState(null);
  const [signer, setSigner] = useState(null);
  const [vault, setVault] = useState({ liquid: "0", wWART: "0", CTSI: "0", eth: "0", pdai: "0" });
  const [burnAmt, setBurnAmt] = useState('');
  const [ethDepositAmt, setEthDepositAmt] = useState('');
  const [withdrawEthAmt, setWithdrawEthAmt] = useState('');
  const [wwartDepositAmt, setWwartDepositAmt] = useState('');
  const [ctsiDepositAmt, setCtsiDepositAmt] = useState('');
  const [pdaiDepositAmt, setPdaiDepositAmt] = useState('');
  const [loading, setLoading] = useState(false);

  // NEW: Toggle for Warthog section (to keep UI optional in Astro island)
  const [showWarthog, setShowWarthog] = useState(false);

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
  const [wartFee, setWartFee] = useState('');
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

  // useEffects FROM ORIGINAL WalletIsland
  useEffect(() => {
    const tryAutoConnect = async () => {
      if (!window.ethereum) return;
      try {
        const prov = new ethers.providers.Web3Provider(window.ethereum);
        const accounts = await prov.listAccounts();
        if (accounts.length > 0) {
          const sign = prov.getSigner();
          const addr = await sign.getAddress();
          setProvider(prov);
          setSigner(sign);
          setAddress(addr);
          setConnected(true);
          toast.success(`Auto-connected: ${addr.slice(0,6)}...${addr.slice(-4)}`);
          refreshVault(addr);
        }
      } catch (err) {
        console.log("No auto-connect");
      }
    };
    tryAutoConnect();
  }, []);

  useEffect(() => {
    if (connected && address) {
      refreshVault(address);
      const interval = setInterval(() => refreshVault(address), 12000);
      return () => clearInterval(interval);
    }
  }, [connected, address]);

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

  // FUNCTIONS FROM ORIGINAL WalletIsland
  const connect = async () => {
    if (!window.ethereum) {
      toast.error("Please install MetaMask!");
      return;
    }

    try {
      try {
        await window.ethereum.request({
          method: 'wallet_addEthereumChain',
          params: [{
            chainId: '0x7a69',
            chainName: 'Cartesi Local',
            rpcUrls: [RPC_URL],
            nativeCurrency: { name: 'ETH', symbol: 'ETH', decimals: 18 },
          }]
        });
      } catch (e) {}

      await window.ethereum.request({ method: 'eth_requestAccounts' });
      const prov = new ethers.providers.Web3Provider(window.ethereum);
      const sign = prov.getSigner();
      const addr = await sign.getAddress();

      setProvider(prov);
      setSigner(sign);
      setAddress(addr);
      setConnected(true);
      toast.success(`Connected: ${addr.slice(0,6)}...${addr.slice(-4)}`);
      refreshVault(addr);
    } catch (err) {
      toast.error("Connection rejected");
      console.error(err);
    }
  };

  const refreshVault = async (addr) => {
    if (!addr) return;
    setLoading(true);
    try {
      const res = await fetch(`${INSPECT_URL}/vault/${addr.slice(2).toLowerCase()}`);
      const data = await res.json();
      if (data.reports?.length > 0) {
        const payload = data.reports[0].payload;
        const json = JSON.parse(ethers.utils.toUtf8String(payload));
        setVault(json);
      }
    } catch (err) {
      console.log("Vault not ready yet");
    } finally {
      setLoading(false);
    }
  };

  const send = async (payload) => {
    if (!signer) {
      toast.error("Wallet not connected!");
      return;
    }
    try {
      setLoading(true);
      const message = JSON.stringify(payload);
      const payloadBytes = ethers.utils.toUtf8Bytes(message);
      const inputBox = new ethers.Contract(INPUT_BOX_ADDRESS, INPUT_BOX_ABI, signer);
      const tx = await inputBox.addInput(DAPP_ADDRESS, payloadBytes, { gasLimit: 200000 });
      const receipt = await tx.wait();
      toast.success(`Sent! Tx: ${receipt.transactionHash.slice(0,10)}...`);
      setTimeout(() => refreshVault(address), 8000);
    } catch (err) {
      toast.error(`Failed: ${err.message || err}`);
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const depositEth = async () => {
    if (!ethDepositAmt || !signer) return;
    try {
      setLoading(true);
      const amountWei = ethers.utils.parseEther(ethDepositAmt);
      const portal = new ethers.Contract(ETHER_PORTAL_ADDRESS, ETHER_PORTAL_ABI, signer);
      const tx = await portal.depositEther(DAPP_ADDRESS, "0x", { value: amountWei, gasLimit: 200000 });
      await tx.wait();
      toast.success('ETH Deposited!');
      setEthDepositAmt('');
      setTimeout(() => refreshVault(address), 8000);
    } catch (err) {
      toast.error(`Failed: ${err.message || err}`);
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const withdrawEth = () => {
    if (!withdrawEthAmt || loading) return;
    send({ type: "withdraw_eth", amount: withdrawEthAmt })
      .then(() => {
        setWithdrawEthAmt('');
        toast.success('Withdrawal request sent! Voucher will be available for L1 claim after rollup processing.');
      });
  };

  const depositErc20 = async (tokenAddress, amountStr, decimals) => {
    if (!amountStr || !signer) return;
    try {
      setLoading(true);
      const amount = ethers.utils.parseUnits(amountStr, decimals);
      const token = new ethers.Contract(tokenAddress, ERC20_ABI, signer);
      const allowance = await token.allowance(address, ERC20_PORTAL_ADDRESS);
      if (allowance.lt(amount)) {
        const txApprove = await token.approve(ERC20_PORTAL_ADDRESS, amount, { gasLimit: 100000 });
        await txApprove.wait();
        toast.success('Approved!');
      }
      const portal = new ethers.Contract(ERC20_PORTAL_ADDRESS, ERC20_PORTAL_ABI, signer);
      const tx = await portal.depositERC20Tokens(tokenAddress, DAPP_ADDRESS, amount, "0x", { gasLimit: 200000 });
      await tx.wait();
      toast.success('Deposited!');
      setTimeout(() => refreshVault(address), 8000);
    } catch (err) {
      toast.error(`Failed: ${err.message || err}`);
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const depositWwart = () => depositErc20(WWART_ADDRESS, wwartDepositAmt, 18).then(() => setWwartDepositAmt(''));
  const depositCtsi = () => depositErc20(CTSI_ADDRESS, ctsiDepositAmt, 18).then(() => setCtsiDepositAmt(''));
  const depositPdai = () => depositErc20(PDAI_ADDRESS, pdaiDepositAmt, 6).then(() => setPdaiDepositAmt(''));

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

      const balanceInWart = balanceData.balance !== undefined ? (balanceData.balance / 1).toFixed(8) : '0';
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
    const { privateKey, publicKey, address } = walletData;
    const walletToSave = { privateKey, publicKey, address };
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
      setWartPassword('');
      setWartSaveConsent(false);
      setWartIsLoggedIn(true);
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
    setWartIsWalletProcessed(true);
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
  };

  const generateWartWallet = async (wordCount, pathType) => {
  const strengthBytes = wordCount === 12 ? 16 : 32;
  const entropy = window.crypto.getRandomValues(new Uint8Array(strengthBytes));
  const mnemonic = ethers.utils.entropyToMnemonic(ethers.utils.hexlify(entropy));
  const path = pathType === 'hardened' ? "m/44'/2070'/0'/0/0" : "m/44'/2070'/0/0/0";
  const hdNode = ethers.utils.HDNode.fromMnemonic(mnemonic).derivePath(path);
  const publicKey = hdNode.publicKey.slice(2);
  const sha = ethers.utils.sha256('0x' + publicKey).slice(2);
  const ripemd = ethers.utils.ripemd160('0x' + sha).slice(2);
  const checksum = ethers.utils.sha256('0x' + ripemd).slice(2, 10);
  const address = ripemd + checksum;
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
    const publicKey = hdNode.publicKey.slice(2);
    const sha = ethers.utils.sha256('0x' + publicKey).slice(2);
    const ripemd = ethers.utils.ripemd160('0x' + sha).slice(2);
    const checksum = ethers.utils.sha256('0x' + ripemd).slice(2, 10);
    const address = ripemd + checksum;
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
    const wallet = new ethers.Wallet('0x' + privKey);
    const publicKey = wallet.publicKey.slice(2);
    const sha = ethers.utils.sha256('0x' + publicKey).slice(2);
    const ripemd = ethers.utils.ripemd160('0x' + sha).slice(2);
    const checksum = ethers.utils.sha256('0x' + ripemd).slice(2, 10);
    const address = ripemd + checksum;
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
    const computedChecksum = ethers.sha256('0x' + ripemdHex).slice(2, 10);
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
    if (wartNonceId === null || wartPinHeight === null || wartPinHash === null) {
      setWartError('Nonce or chain head not available. Please refresh balance and try again.');
      return;
    }
    try {
      const pinHashBytes = ethers.getBytes('0x' + wartPinHash);
      const heightBytes = new Uint8Array(4);
      new DataView(heightBytes.buffer).setUint32(0, wartPinHeight, false);
      const nonceBytes = new Uint8Array(4);
      new DataView(nonceBytes.buffer).setUint32(0, wartNonceId, false);
      const reserved = new Uint8Array(3);
      const feeBytes = new Uint8Array(8);
      new DataView(feeBytes.buffer).setBigUint64(0, BigInt(feeE8), false);
      const toRawBytes = ethers.getBytes('0x' + wartToAddr.slice(0, 40));
      const amountBytes = new Uint8Array(8);
      new DataView(amountBytes.buffer).setBigUint64(0, BigInt(amountE8), false);

      const messageBytes = ethers.concat([
        pinHashBytes,
        heightBytes,
        nonceBytes,
        reserved,
        feeBytes,
        toRawBytes,
        amountBytes,
      ]);

      const txHash = ethers.sha256(messageBytes);
      const txHashBytes = ethers.getBytes(txHash);

      const signer = new ethers.Wallet('0x' + txPrivateKey);
      const sig = signer.signingKey.sign(txHashBytes);

      const rHex = sig.r.slice(2);
      const sHex = sig.s.slice(2);
      const recid = sig.v - 27;
      const recidHex = recid.toString(16).padStart(2, '0');
      const signature65 = rHex + sHex + recidHex;

      const nodeBaseParam = `nodeBase=${encodeURIComponent(wartSelectedNode)}`;
      console.log('Sending transaction request to:', `${API_URL}?nodePath=transaction/add&${nodeBaseParam}`);
      const response = await axios.post(
        `${API_URL}?nodePath=transaction/add&${nodeBaseParam}`,
        {
          pinHeight: wartPinHeight,
          nonceId: wartNonceId,
          toAddr: wartToAddr,
          amountE8,
          feeE8,
          signature65,
        },
        { headers: { 'Content-Type': 'application/json' } }
      );
      console.log('Send transaction response status:', response.status);
      const data = response.data;
      console.log('Send transaction response data:', data);
      setWartSendResult(data);
      // Clear input fields on success
      setWartToAddr('');
      setWartAmount('');
      setWartFee('');
      if (wartWallet?.address) {
        fetchWartBalanceAndNonce(wartWallet.address);
      }
    } catch (err) {
      const errorMessage =
        err.response?.data?.message ||
        err.message ||
        'Failed to send transaction';
      setWartError(errorMessage);
      console.error('Fetch send transaction error:', err);
    }
  };

  const handleWartInstallClick = async () => {
    if (wartDeferredPrompt) {
      wartDeferredPrompt.prompt();
      const { outcome } = await wartDeferredPrompt.userChoice;
      if (outcome === 'accepted') {
        console.log('User accepted the install prompt');
      } else {
        console.log('User dismissed the install prompt');
      }
      setWartDeferredPrompt(null);
    }
  };

  // NEW: Relayer Functions (Bridge Warthog to Liquid/Cartesi)
  const getWartTxProof = async (txHash) => {
    const nodeBaseParam = `nodeBase=${encodeURIComponent(wartSelectedNode)}`;
    try {
      const response = await axios.get(`${API_URL}?nodePath=transaction/${txHash}&${nodeBaseParam}`);
      return response.data.data || response.data; // Adjust based on Warthog response format for proof
    } catch (err) {
      throw new Error('Failed to fetch tx proof');
    }
  };

  const depositNativeWart = async () => {
    if (!wartAmount || !wartWallet) return toast.error('Enter amount and load Warthog wallet');
    setLoading(true);
    try {
      setWartToAddr(BRIDGE_ADDRESS);
      setWartFee('0.0001'); // Example default fee, can make input
      await handleSendWartTransaction();
      toast.success('WART deposited to bridge on Warthog! Now relay proof.');
    } catch (err) {
      toast.error('Warthog deposit failed');
    } finally {
      setLoading(false);
    }
  };

  const [wartTxHashForRelay, setWartTxHashForRelay] = useState('');

  const relayWartDepositProof = async () => {
    if (!wartTxHashForRelay || !signer) return toast.error('Enter Warthog tx hash and connect MetaMask');
    setLoading(true);
    try {
      const proof = await getWartTxProof(wartTxHashForRelay);
      const payload = { type: 'wart_deposit', proof, recipient: address };
      await send(payload); // Uses original send() for Cartesi input
      toast.success('Proof relayed to Liquid dApp! Voucher pending.');
      setWartTxHashForRelay('');
    } catch (err) {
      toast.error('Relay failed');
    } finally {
      setLoading(false);
    }
  };

  // Formatted values from original
  const format = (val, decimals) => Number(ethers.utils.formatUnits(val || "0", decimals));
  const liquid = format(vault.liquid, 18);
  const wWART = format(vault.wWART, 18);
  const CTSI = format(vault.CTSI, 18);
  const eth = Number(vault.eth || 0);
  const pdai = format(vault.pdai, 6);  // assuming PDAI has 6 decimals

  const totalBacking = wWART + CTSI + eth + pdai;
  const wwartPct = totalBacking > 0 ? (wWART / totalBacking * 100).toFixed(1) : 0;
  const ctsiPct = totalBacking > 0 ? (CTSI / totalBacking * 100).toFixed(1) : 0;
  const ethPct = totalBacking > 0 ? (eth / totalBacking * 100).toFixed(1) : 0;
  const pdaiPct = totalBacking > 0 ? (pdai / totalBacking * 100).toFixed(1) : 0;

  if (!connected) {
    return (
      <div className="preview-section">
        <Toaster position="top-right" />
        <button onClick={connect} className="btn primary text-xl px-12 py-6 mb-12">
          <Wallet className="inline mr-4" size={28} />
          Connect Wallet
        </button>
        <div className="card preview-card">
          <p className="preview-label">Preview — Connect to load your vault</p>
          <div className="grid">
            <div className="box yellow"><Coins size={64} className="mx-auto mb-3" /><p className="big">1,500</p><p>LIQUID</p></div>
            <div className="box teal"><p className="big">50%</p><p>wWART</p><p className="text-2xl font-bold mt-2">750</p></div>
            <div className="box teal"><p className="big">30%</p><p>CTSI</p><p className="text-2xl font-bold mt-2">450</p></div>
            <div className="box purple"><p className="big">20%</p><p>ETH</p><p className="text-2xl font-bold mt-2">0.12</p></div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="vault-section">
      <Toaster position="top-right" />
      <p className="connected-address">Connected: {address.slice(0,6)}...{address.slice(-4)}</p>

      <div style={{ textAlign: 'center', margin: '30px 0' }}>
        <button onClick={() => send({ type: "register_address" })} className="register-address-btn" disabled={loading}>
          Register My Address with DApp
        </button>
      </div>

      <div className="card">
        <div className="grid">
          <div className="box yellow">
            <Coins size={64} className="mx-auto mb-3" />
            <p className="big">{liquid.toLocaleString(undefined, {maximumFractionDigits: 0})}</p>
            <p>LIQUID Balance</p>
          </div>
          <div className="box teal">
            <p className="big">{wwartPct}%</p>
            <p>wWART Backing</p>
            <p className="text-2xl font-bold mt-2">{wWART.toFixed(4)}</p>
          </div>
          <div className="box teal">
            <p className="big">{ctsiPct}%</p>
            <p>CTSI Backing</p>
            <p className="text-2xl font-bold mt-2">{CTSI.toFixed(4)}</p>
          </div>
          <div className="box purple">
            <p className="big">{ethPct}%</p>
            <p>ETH Backing</p>
            <p className="text-2xl font-bold mt-2">{eth.toFixed(6)}</p>
          </div>
          <div className="box blue">
            <p className="big">{pdaiPct}%</p>
            <p>PDAI Backing</p>
            <p className="text-2xl font-bold mt-2">{pdai.toFixed(4)}</p>
          </div>
        </div>

        <div className="actions">
          <button onClick={() => send({ type: "mint_liquid" })} className="btn primary" disabled={loading}>
            <Zap className="inline mr-3" size={26} /> Mint LIQUID
          </button>
          <input
            type="number"
            placeholder="Amount to burn"
            value={burnAmt}
            onChange={(e) => setBurnAmt(e.target.value)}
            style={{ padding: '12px', margin: '0 12px', borderRadius: '8px', border: '1px solid #555', width: '140px' }}
          />
          <button onClick={() => burnAmt && send({ type: "burn_liquid", amount: burnAmt })} className="btn danger" disabled={!burnAmt || loading}>
            <ArrowDown className="inline mr-3" size={26} /> Burn & Redeem
          </button>
        </div>

        <div style={{ textAlign: 'center', marginTop: '20px' }}>
          <button onClick={() => refreshVault(address)} className="btn small" disabled={loading}>
            <RefreshCw size={18} className="inline mr-2" /> Refresh Vault
          </button>
        </div>
      </div>

      {/* Deposit Section */}
      <div className="deposit-section" style={{ marginTop: '40px' }}>
        <h2 style={{ textAlign: 'center', marginBottom: '20px' }}>Deposit Backing Assets</h2>
        <div className="grid" style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '20px' }}>
          <div className="deposit-box">
            <p>ETH</p>
            <input
              type="number"
              placeholder="Amount"
              value={ethDepositAmt}
              onChange={(e) => setEthDepositAmt(e.target.value)}
              style={{ padding: '8px', marginRight: '10px', width: '100px' }}
            />
            <button onClick={depositEth} className="btn primary small" disabled={loading}>Deposit</button>
            {/* Withdrawal Section */}
<div className="withdraw-section" style={{ marginTop: '40px' }}>
  <h2 style={{ textAlign: 'center', marginBottom: '20px' }}>Withdraw ETH (Trustless Voucher)</h2>
  <div className="deposit-box" style={{ display: 'flex', justifyContent: 'center', alignItems: 'center' }}>
    <p>ETH Amount:</p>
    <input
      type="number"
      placeholder="Amount"
      value={withdrawEthAmt}
      onChange={(e) => setWithdrawEthAmt(e.target.value)}
      style={{ padding: '8px', margin: '0 10px', width: '100px' }}
    />
    <button onClick={withdrawEth} className="btn danger small" disabled={loading || !withdrawEthAmt}>Withdraw</button>
  </div>
  <p style={{ textAlign: 'center', marginTop: '10px', fontSize: '12px', color: '#aaa' }}>
    Note: After submission, monitor for the voucher in your wallet or L1 explorer. Execute it trustlessly on L1.
  </p>
</div>
          </div>
          
          <div className="deposit-box">
            <p>wWART</p>
            <input
              type="number"
              placeholder="Amount"
              value={wwartDepositAmt}
              onChange={(e) => setWwartDepositAmt(e.target.value)}
              style={{ padding: '8px', marginRight: '10px', width: '100px' }}
            />
            <button onClick={depositWwart} className="btn primary small" disabled={loading}>Deposit</button>
          </div>
          <div className="deposit-box">
            <p>CTSI</p>
            <input
              type="number"
              placeholder="Amount"
              value={ctsiDepositAmt}
              onChange={(e) => setCtsiDepositAmt(e.target.value)}
              style={{ padding: '8px', marginRight: '10px', width: '100px' }}
            />
            <button onClick={depositCtsi} className="btn primary small" disabled={loading}>Deposit</button>
          </div>
          <div className="deposit-box">
            <p>PDAI</p>
            <input
              type="number"
              placeholder="Amount"
              value={pdaiDepositAmt}
              onChange={(e) => setPdaiDepositAmt(e.target.value)}
              style={{ padding: '8px', marginRight: '10px', width: '100px' }}
            />
            <button onClick={depositPdai} className="btn primary small" disabled={loading}>Deposit</button>
          </div>
        </div>
      </div>

      {/* NEW: Toggle for Warthog Section */}
      <div style={{ textAlign: 'center', margin: '30px 0' }}>
        <button onClick={() => setShowWarthog(!showWarthog)} className="btn primary">
          {showWarthog ? 'Hide' : 'Show'} Warthog Native Wallet & Bridge
        </button>
      </div>

      {showWarthog && (
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
                  placeholder="Enter fee in WART (e.g., 0.0001)"
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
      )}
    </div>
  );
}