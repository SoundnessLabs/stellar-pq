import { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Wallet, RefreshCw, Check, ExternalLink, Loader2 } from 'lucide-react'
import { cn, truncateAddress } from '@/lib/utils'
import { fundSmartAccount, getSmartAccountBalance, type FundResult } from '@/lib/stellar/smart-account'
import { toast } from 'sonner'

interface FundAccountProps {
  contractId: string | null
  onFunded: (balance: string) => void
  isActive: boolean
}

export function FundAccount({ contractId, onFunded, isActive }: FundAccountProps) {
  const [isFunding, setIsFunding] = useState(false)
  const [isRefreshing, setIsRefreshing] = useState(false)
  const [balance, setBalance] = useState<string | null>(null)
  const [result, setResult] = useState<FundResult | null>(null)
  const [fundAmount, setFundAmount] = useState('10')

  // Fetch balance when contract ID changes
  useEffect(() => {
    if (contractId && isActive) {
      refreshBalance()
    }
  }, [contractId, isActive])

  const refreshBalance = async () => {
    if (!contractId) return

    setIsRefreshing(true)
    try {
      const balanceResult = await getSmartAccountBalance(contractId)
      if (balanceResult.success && balanceResult.balance) {
        setBalance(balanceResult.balance)
        if (parseFloat(balanceResult.balance) > 0) {
          onFunded(balanceResult.balance)
        }
      }
    } catch (error) {
      console.error('Balance fetch error:', error)
    } finally {
      setIsRefreshing(false)
    }
  }

  const handleFund = async () => {
    if (!contractId) {
      toast.error('Please deploy a smart account first')
      return
    }

    const amount = parseFloat(fundAmount)
    if (isNaN(amount) || amount <= 0) {
      toast.error('Please enter a valid amount')
      return
    }

    setIsFunding(true)
    setResult(null)

    try {
      const fundResult = await fundSmartAccount(contractId, amount)
      setResult(fundResult)

      if (fundResult.success) {
        toast.success(`Funded with ${amount} XLM!`)
        await refreshBalance()
      } else {
        toast.error(fundResult.error || 'Funding failed')
      }
    } catch (error) {
      console.error('Funding error:', error)
      toast.error('Failed to fund smart account')
      setResult({
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
      })
    } finally {
      setIsFunding(false)
    }
  }

  return (
    <div className="space-y-6">
      {/* Contract Info */}
      {contractId && (
        <div className="p-4 bg-muted rounded-xl">
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm text-muted-foreground">Smart Account</span>
            <a
              href={`https://stellar.expert/explorer/testnet/contract/${contractId}`}
              target="_blank"
              rel="noopener noreferrer"
              className="text-soundness-blue hover:text-soundness-blue-light transition-colors"
            >
              <ExternalLink size={14} />
            </a>
          </div>
          <p className="font-mono text-sm text-white">
            {truncateAddress(contractId, 12, 12)}
          </p>
        </div>
      )}

      {/* Balance Display */}
      {contractId && (
        <div className="p-4 bg-muted rounded-xl">
          <div className="flex items-center justify-between">
            <div>
              <span className="text-sm text-muted-foreground">Current Balance</span>
              <p className="text-2xl font-bold text-white">
                {balance !== null ? `${balance} XLM` : '---'}
              </p>
            </div>
            <button
              onClick={refreshBalance}
              disabled={isRefreshing}
              className="p-2 bg-white/10 rounded-lg hover:bg-white/20 transition-colors"
            >
              <RefreshCw size={18} className={cn(isRefreshing && 'animate-spin')} />
            </button>
          </div>
        </div>
      )}

      {/* Fund Amount Input */}
      {contractId && (
        <div>
          <label className="block text-sm text-muted-foreground mb-2">
            Amount to Fund (XLM)
          </label>
          <div className="flex gap-3">
            <input
              type="number"
              value={fundAmount}
              onChange={(e) => setFundAmount(e.target.value)}
              placeholder="10"
              min="1"
              max="100"
              className="input-field flex-1"
            />
            <button
              onClick={handleFund}
              disabled={isFunding}
              className="btn-primary"
            >
              {isFunding ? (
                <span className="flex items-center gap-2">
                  <Loader2 size={18} className="animate-spin" />
                  Funding...
                </span>
              ) : (
                <span className="flex items-center gap-2">
                  <Wallet size={18} />
                  Fund
                </span>
              )}
            </button>
          </div>
        </div>
      )}

      {/* Result Display */}
      <AnimatePresence>
        {result && (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            className={cn(
              'p-4 rounded-xl border',
              result.success
                ? 'bg-success/10 border-success/50'
                : 'bg-error/10 border-error/50'
            )}
          >
            {result.success ? (
              <div className="space-y-2">
                <div className="flex items-center gap-2 text-success">
                  <Check size={20} />
                  <span className="font-semibold">Account Funded!</span>
                </div>
                <p className="text-sm text-muted-foreground">
                  Added {result.amount} to the smart account
                </p>
                {result.explorerUrl && (
                  <a
                    href={result.explorerUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 text-sm text-soundness-blue hover:text-soundness-blue-light transition-colors"
                  >
                    View Transaction <ExternalLink size={14} />
                  </a>
                )}
              </div>
            ) : (
              <div className="text-error">
                <span className="font-semibold">Funding Failed</span>
                <p className="text-sm mt-1">{result.error}</p>
              </div>
            )}
          </motion.div>
        )}
      </AnimatePresence>

      {/* Disabled State */}
      {!contractId && (
        <div className="p-4 bg-muted/50 rounded-xl text-center text-muted-foreground text-sm">
          Loading smart account...
        </div>
      )}
    </div>
  )
}
