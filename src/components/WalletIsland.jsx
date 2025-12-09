// src/components/WalletIsland.jsx
import { useState, useEffect } from 'react';
import axios from 'axios';
import { Wallet, Zap, ArrowDown, Coins } from 'lucide-react';

// This line fixes CSS loading in the React island
import '../styles/global.css';

const INPUT_URL = "http://localhost:8080/input";
const INSPECT_URL = "http://localhost:8080/inspect";

export default function WalletIsland() {
  const [address, setAddress] = useState('');
  const [vault, setVault] = useState({ liquid: "0", wWART: "0", CTSI: "0" });
  const [burnAmt, setBurnAmt] = useState('');

  const connect = async () => {
    if (!window.ethereum) return alert("Install MetaMask");
    try {
      await window.ethereum.request({ method: 'eth_requestAccounts' });
      const provider = new ethers.providers.Web3Provider(window.ethereum);
      const signer = provider.getSigner();
      const addr = await signer.getAddress();
      setAddress(addr);
      fetchVault(addr);
      const interval = setInterval(() => fetchVault(addr), 10000);
      return () => clearInterval(interval);
    } catch (err) {
      alert("Connection failed");
    }
  };

  const fetchVault = async (addr) => {
    try {
      const res = await axios.get(`${INSPECT_URL}/vault/${addr.toLowerCase()}`);
      if (res.data.reports?.[0]?.payload) {
        const json = JSON.parse(ethers.utils.toUtf8String(res.data.reports[0].payload));
        setVault(json);
      }
    } catch (e) {
      console.log("No vault yet");
    }
  };

  const send = async (payload) => {
    try {
      const hex = "0x" + Buffer.from(JSON.stringify(payload)).toString("hex");
      await axios.post(INPUT_URL, { payload: hex });
      setTimeout(() => address && fetchVault(address), 6000);
    } catch (err) {
      alert("Failed to send");
    }
  };

  const total = Number(vault.wWART) + Number(vault.CTSI);
  const wwartPct = total > 0 ? (Number(vault.wWART) / total * 100).toFixed(1) : 0;
  const ctsiPct = total > 0 ? (100 - wwartPct).toFixed(1) : 0;

  if (!address) {
    return (
      <div className="preview-section">
        <button onClick={connect} className="btn primary text-xl px-12 py-6 mb-12">
          <Wallet className="inline mr-4" size={28} />
          Connect Wallet
        </button>

        <div className="card preview-card">
          <p className="preview-label">Preview — Connect to load your vault</p>
          <div className="grid">
            <div className="box yellow">
              <Coins size={64} className="mx-auto mb-3" />
              <p className="big">1,500</p>
              <p>LIQUID</p>
            </div>
            <div className="box teal">
              <p className="big">67.3%</p>
              <p>wWART</p>
              <p className="text-2xl font-bold mt-2">1,010.5</p>
            </div>
            <div className="box teal">
              <p className="big">32.7%</p>
              <p>CTSI</p>
              <p className="text-2xl font-bold mt-2">489.0</p>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="vault-section">
      <p className="connected-address">
        Connected: {address.slice(0,6)}...{address.slice(-4)}
      </p>

      <div className="card">
        <div className="grid">
          <div className="box yellow">
            <Coins size={64} className="mx-auto mb-3" />
            <p className="big">{Number(vault.liquid).toLocaleString()}</p>
            <p>LIQUID Balance</p>
          </div>
          <div className="box teal">
            <p className="big">{wwartPct}%</p>
            <p>wWART Backing</p>
            <p className="text-2xl font-bold mt-2">{Number(vault.wWART).toFixed(4)}</p>
          </div>
          <div className="box teal">
            <p className="big">{ctsiPct}%</p>
            <p>CTSI Backing</p>
            <p className="text-2xl font-bold mt-2">{Number(vault.CTSI).toFixed(4)}</p>
          </div>
        </div>

        <div className="actions">
          <button onClick={() => send({type: "mint_liquid"})} className="btn primary">
            <Zap className="inline mr-3" size={26} />
            Mint LIQUID
          </button>
          <input
            type="number"
            placeholder="Amount"
            value={burnAmt}
            onChange={e => setBurnAmt(e.target.value)}
          />
          <button
            onClick={() => burnAmt && send({type: "burn_liquid", amount: burnAmt})}
            className="btn danger"
          >
            <ArrowDown className="inline mr-3" size={26} />
            Burn & Redeem
          </button>
        </div>
      </div>
    </div>
  );
}