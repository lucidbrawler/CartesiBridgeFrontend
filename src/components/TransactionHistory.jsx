// TransactionHistory.jsx
import React, { useState, useEffect } from 'react';
import axios from 'axios';

const API_URL = '/api/proxy';
const PAGE_SIZE = 15;

const TransactionHistory = ({ address, node, isPolling }) => {
  const [allHistory, setAllHistory] = useState([]); // Accumulate all fetched transactions
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);
  const [nextCursor, setNextCursor] = useState('4294967295'); // Start with large number
  const [hasMore, setHasMore] = useState(true);
  const [currentPage, setCurrentPage] = useState(1);

  useEffect(() => {
    if (address && node && allHistory.length === 0) {
      fetchMoreHistory();
    }
  }, [address, node]);

  const fetchMoreHistory = async () => {
    if (!hasMore || loading) return;
    setLoading(true);
    try {
      const nodeBaseParam = `nodeBase=${encodeURIComponent(node)}`;
      const path = `account/${address}/history/${nextCursor}`;
      const response = await axios.get(`${API_URL}?nodePath=${path}&${nodeBaseParam}`, {
        headers: { 'Content-Type': 'application/json' },
      });
      const rawData = response.data.data || response.data;
      if (rawData.perBlock && Array.isArray(rawData.perBlock)) {
        const newItems = rawData.perBlock.flatMap(block => 
          (block.transactions.transfers || []).map(tx => ({
            ...tx,
            confirmations: block.confirmations,
            height: block.height,
            txid: tx.txHash, // Use txHash as txid
          }))
        );
        setAllHistory(prev => [...prev, ...newItems]);
        setHasMore(newItems.length > 0 && rawData.fromId > 0);
        setNextCursor(rawData.fromId > 0 ? rawData.fromId : null);
      } else {
        setError('Unexpected response format');
      }
    } catch (err) {
      setError(err.response?.data?.message || err.message || 'Failed to fetch transaction history');
    } finally {
      setLoading(false);
    }
  };

  const handleNext = () => {
    const nextPage = currentPage + 1;
    const requiredLength = nextPage * PAGE_SIZE;
    if (allHistory.length < requiredLength && hasMore) {
      fetchMoreHistory();
    }
    if (allHistory.length >= requiredLength || (allHistory.length < requiredLength && !hasMore)) {
      setCurrentPage(nextPage);
    }
  };

  const handlePrev = () => {
    if (currentPage > 1) {
      setCurrentPage(currentPage - 1);
    }
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text).then(() => {
      alert('Copied to clipboard!');
    }).catch(err => {
      console.error('Failed to copy: ', err);
    });
  };

  const startIndex = (currentPage - 1) * PAGE_SIZE;
  const endIndex = startIndex + PAGE_SIZE;
  const currentHistory = allHistory.slice(startIndex, endIndex);
  const hasNext = (endIndex < allHistory.length) || hasMore;

  return (
    <section style={{ fontFamily: 'Montserrat', color: '#FFECB3' }}>
      <h2 style={{ color: '#caa21eff' }}>Transaction History (Page {currentPage}) <span style={{ display: 'inline-block', width: '8px', height: '8px', backgroundColor: isPolling ? 'yellow' : 'green', borderRadius: '50%', marginLeft: '8px', animation: isPolling ? 'blink 1s infinite' : 'none' }}></span></h2>
      {loading && <p>Loading...</p>}
      {error && <div className="error"><strong>Error:</strong> {error}</div>}
      {allHistory.length === 0 && !loading && <p>No transactions found.</p>}
      {currentHistory.length > 0 && (
        <div style={{ maxHeight: '400px', overflowY: 'auto', paddingRight: '10px' }}>
          {currentHistory.map((tx, index) => (
            <div 
              key={index} 
              style={{ 
                backgroundColor: '#ffecb33d', 
                border: '1px solid #caa21eff', 
                borderRadius: '8px', 
                padding: '16px', 
                marginBottom: '16px', 
                color: '#e9e6dbff' 
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px' }}>
                <strong style={{ color: '#caa21eff' }}>TxID:</strong>
                <span 
                  title={tx.txid || 'N/A'} 
                  style={{ cursor: 'pointer' }} 
                  onClick={() => copyToClipboard(tx.txid || '')}
                >
                  {tx.txid ? `${tx.txid.slice(0, 6)}...${tx.txid.slice(-6)}` : 'N/A'}
                </span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px' }}>
                <strong style={{ color: '#caa21eff' }}>From:</strong>
                <span 
                  title={tx.fromAddress || 'N/A'} 
                  style={{ cursor: 'pointer' }} 
                  onClick={() => copyToClipboard(tx.fromAddress || '')}
                >
                  {tx.fromAddress ? `${tx.fromAddress.slice(0, 6)}...${tx.fromAddress.slice(-6)}` : 'N/A'}
                </span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px' }}>
                <strong style={{ color: '#caa21eff' }}>To:</strong>
                <span 
                  title={tx.toAddress || 'N/A'} 
                  style={{ cursor: 'pointer' }} 
                  onClick={() => copyToClipboard(tx.toAddress || '')}
                >
                  {tx.toAddress ? `${tx.toAddress.slice(0, 6)}...${tx.toAddress.slice(-6)}` : 'N/A'}
                </span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px' }}>
                <strong style={{ color: '#caa21eff' }}>Amount (WART):</strong>
                <span>{tx.amount !== undefined ? parseFloat(tx.amount).toFixed(8) : 'N/A'}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px' }}>
                <strong style={{ color: '#caa21eff' }}>Fee (WART):</strong>
                <span>{tx.fee !== undefined ? parseFloat(tx.fee).toFixed(8) : 'N/A'}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px' }}>
                <strong style={{ color: '#caa21eff' }}>Confirmations:</strong>
                <span>{tx.confirmations || 'N/A'}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <strong style={{ color: '#caa21eff' }}>Height:</strong>
                <span>{tx.height || 'N/A'}</span>
              </div>
            </div>
          ))}
        </div>
      )}
      <div>
        <button onClick={handlePrev} disabled={currentPage === 1 || loading}>
          Previous
        </button>
        <button onClick={handleNext} disabled={!hasNext || loading}>
          Next
        </button>
      </div>
    </section>
  );
};

export default TransactionHistory;
