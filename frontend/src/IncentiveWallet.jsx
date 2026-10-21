import { useState, useEffect, useCallback } from "react";
import {
  Wallet, TrendingUp, TrendingDown, Trophy, RefreshCw,
  Loader2, ArrowUpRight, ArrowDownRight, Star, Shield,
} from "lucide-react";
import { API_BASE_URL, getAccessToken } from "./api";
import "./IncentiveWallet.css";

const hdrs = () => ({ Authorization: `Bearer ${getAccessToken()}` });

const REASON_LABELS = {
  shared_cti: { label: "Shared CTI Record", icon: ArrowUpRight, color: "#6ee7b7" },
  high_confidence_bonus: { label: "High-Confidence Bonus", icon: Star, color: "#a78bfa" },
  cross_sector_bonus: { label: "Cross-Sector Sharing", icon: TrendingUp, color: "#38bdf8" },
  policy_violation: { label: "Policy Violation", icon: ArrowDownRight, color: "#f87171" },
  access_revocation: { label: "Access Revocation", icon: Shield, color: "#ef4444" },
};

export default function IncentiveWallet() {
  const [wallet, setWallet] = useState(null);
  const [transactions, setTransactions] = useState([]);
  const [leaderboard, setLeaderboard] = useState([]);
  const [loading, setLoading] = useState(true);
  const [tab, setTab] = useState("wallet");

  const load = useCallback(async () => {
    const [wRes, lRes] = await Promise.all([
      fetch(`${API_BASE_URL}/api/incentive/wallet`, { headers: hdrs() }),
      fetch(`${API_BASE_URL}/api/incentive/leaderboard`, { headers: hdrs() }),
    ]);
    if (wRes.ok) {
      const d = await wRes.json();
      setWallet(d.wallet);
      setTransactions(d.transactions || []);
    }
    if (lRes.ok) {
      const d = await lRes.json();
      setLeaderboard(d.leaderboard || []);
    }
    setLoading(false);
  }, []);

  useEffect(() => { load(); }, [load]);

  if (loading) return <div className="iw-loading"><Loader2 className="spin" size={24} /> Loading wallet...</div>;

  const balance = wallet?.balance || 0;
  const tier = balance >= 100 ? "Premium" : balance >= 50 ? "Standard" : "Basic";
  const tierColor = tier === "Premium" ? "#a78bfa" : tier === "Standard" ? "#38bdf8" : "#94a3b8";
  const tierNext = tier === "Basic" ? 50 : tier === "Standard" ? 100 : null;
  const progress = tierNext ? (balance / tierNext) * 100 : 100;

  return (
    <div className="iw-page">
      <div className="iw-header">
        <h2><Wallet size={22} /> Incentive Wallet</h2>
        <p>Earn tokens by sharing quality CTI. Higher balance unlocks better access tiers. Violations and revocations cost tokens.</p>
      </div>

      <div className="iw-tabs">
        <button className={tab === "wallet" ? "active" : ""} onClick={() => setTab("wallet")}>
          <Wallet size={14} /> My Wallet
        </button>
        <button className={tab === "leaderboard" ? "active" : ""} onClick={() => setTab("leaderboard")}>
          <Trophy size={14} /> Leaderboard
        </button>
      </div>

      {tab === "wallet" && (
        <>
          {/* Wallet Card */}
          <div className="iw-wallet-card">
            <div className="iw-wallet-bg" />
            <div className="iw-wallet-content">
              <div className="iw-wallet-top">
                <span className="iw-wallet-label">CTI Sharing Wallet</span>
                <span className="iw-tier" style={{ color: tierColor, borderColor: tierColor }}>{tier}</span>
              </div>
              <div className="iw-balance">
                <span className="iw-balance-amount">${balance.toFixed(2)}</span>
                <span className="iw-balance-label">Token Balance</span>
              </div>
              <div className="iw-wallet-stats">
                <div>
                  <small>Lifetime Earned</small>
                  <strong style={{ color: "#6ee7b7" }}>+${(wallet?.lifetime_earned || 0).toFixed(2)}</strong>
                </div>
                <div>
                  <small>Lifetime Spent</small>
                  <strong style={{ color: "#f87171" }}>-${(wallet?.lifetime_spent || 0).toFixed(2)}</strong>
                </div>
              </div>
              {tierNext && (
                <div className="iw-tier-progress">
                  <div className="iw-tier-bar">
                    <div className="iw-tier-fill" style={{ width: `${Math.min(progress, 100)}%` }} />
                  </div>
                  <small>${balance.toFixed(0)} / ${tierNext} for {tier === "Basic" ? "Standard" : "Premium"} tier</small>
                </div>
              )}
            </div>
          </div>

          {/* Token Schedule */}
          <div className="iw-schedule">
            <h3>Token Schedule</h3>
            <div className="iw-schedule-grid">
              <div className="iw-sched-item earn"><span>+$10</span> Share a CTI record</div>
              <div className="iw-sched-item earn"><span>+$5</span> High-confidence bonus</div>
              <div className="iw-sched-item earn"><span>+$3</span> Cross-sector sharing</div>
              <div className="iw-sched-item penalty"><span>-$20</span> Policy violation</div>
              <div className="iw-sched-item penalty"><span>-$50</span> Access revocation</div>
            </div>
          </div>

          {/* Transaction History */}
          <div className="iw-txns">
            <h3>Transaction History</h3>
            {transactions.length === 0 ? (
              <p className="iw-empty">No transactions yet. Share CTI to start earning!</p>
            ) : (
              <div className="iw-txn-list">
                {transactions.map(tx => {
                  const info = REASON_LABELS[tx.reason] || { label: tx.reason, icon: ArrowUpRight, color: "#94a3b8" };
                  const Icon = info.icon;
                  const positive = tx.amount > 0;
                  return (
                    <div key={tx.id} className={`iw-txn ${positive ? "earn" : "penalty"}`}>
                      <div className="iw-txn-icon" style={{ color: info.color }}>
                        <Icon size={16} />
                      </div>
                      <div className="iw-txn-detail">
                        <strong>{info.label}</strong>
                        {tx.reference_id && <small>Record #{tx.reference_id}</small>}
                      </div>
                      <div className="iw-txn-amount" style={{ color: positive ? "#6ee7b7" : "#f87171" }}>
                        {positive ? "+" : ""}${tx.amount.toFixed(2)}
                      </div>
                      <div className="iw-txn-bal">
                        ${tx.balance_after.toFixed(2)}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </>
      )}

      {tab === "leaderboard" && (
        <div className="iw-leaderboard">
          <h3><Trophy size={16} /> Contribution Leaderboard</h3>
          <div className="iw-lb-list">
            {leaderboard.map((entry, i) => (
              <div key={entry.organization_id} className={`iw-lb-row ${i === 0 ? "first" : ""}`}>
                <div className="iw-lb-rank">#{entry.rank}</div>
                <div className="iw-lb-info">
                  <strong>{entry.name}</strong>
                  <small>{entry.sector} · Trust: {entry.trust_score}</small>
                </div>
                <div className="iw-lb-tier" style={{ color: entry.tier === "Premium" ? "#a78bfa" : entry.tier === "Standard" ? "#38bdf8" : "#94a3b8" }}>
                  {entry.tier}
                </div>
                <div className="iw-lb-balance">${entry.balance.toFixed(2)}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      <button className="iw-refresh" onClick={load}>
        <RefreshCw size={14} /> Refresh
      </button>
    </div>
  );
}
