// src/components/WalletIsland.jsx — MERGED WITH WARTHOG WALLET FOR ASTRO (December 2025)
// Updated with class-based styles for Warthog section
// Refactored: Extracted WarthogWallet and SubWallet as separate components
// README: This is the main component for the WalletIsland DApp, handling connection to MetaMask, vault management, deposits/withdrawals for backing assets, and toggling the Warthog native wallet section. It integrates Cartesi rollup interactions via portals and inputs. The Warthog section is conditionally rendered via a toggle, and it passes necessary props like the 'send' function for relaying proofs to the extracted WarthogWallet component.

import { useState, useEffect } from 'react';
import { Wallet, Zap, ArrowDown, Coins, RefreshCw } from 'lucide-react';
import { Toaster, toast } from 'react-hot-toast';
import { ethers } from 'ethers';
import WarthogWallet from './WarthogWallet'; // Added import for WarthogWallet component
import '../styles/global.css'; // Assuming global styles (including new Warthog CSS) in Astro
import '../styles/warthog.css';
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
        <WarthogWallet 
          send={send} // Pass the send function for relaying proofs
          address={address} // Pass L1 address for relay
          loading={loading}
          setLoading={setLoading}
        />
      )}
    </div>
  );
}