import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Send, Check, ExternalLink, Loader2, AlertCircle } from 'lucide-react'
import { cn, truncateAddress, isValidStellarAddress } from '@/lib/utils'
import { transferFromSmartAccount, type TransferResult, type TransferStep } from '@/lib/stellar/smart-account'
import { getDemoAccountPublicKey } from '@/lib/stellar/config'
import { toast } from 'sonner'

interface TransferXLMProps {
  contractId: string | null
  seed: Uint8Array | null
  balance: string | null
  isActive: boolean
}

export function TransferXLM({ contractId, seed, balance, isActive: _isActive }: TransferXLMProps) {
  const [recipient, setRecipient] = useState(getDemoAccountPublicKey())
  const [amount, setAmount] = useState('1')
  const [isTransferring, setIsTransferring] = useState(false)
  const [result, setResult] = useState<TransferResult | null>(null)
  const [steps, setSteps] = useState<TransferStep[]>([])

  const canTransfer = contractId && seed && balance && parseFloat(balance) > 0

  const handleTransfer = async () => {
    if (!contractId || !seed) {
      toast.error('Missing contract ID or seed')
      return
    }

    if (!isValidStellarAddress(recipient)) {
      toast.error('Invalid recipient address')
      return
    }

    const amountXLM = parseFloat(amount)
    if (isNaN(amountXLM) || amountXLM <= 0) {
      toast.error('Please enter a valid amount')
      return
    }

    if (balance && amountXLM > parseFloat(balance)) {
      toast.error('Insufficient balance')
      return
    }

    setIsTransferring(true)
    setResult(null)
    setSteps([])

    try {
      const transferResult = await transferFromSmartAccount(
        contractId,
        recipient,
        amountXLM,
        seed,
        (updatedSteps) => setSteps([...updatedSteps])
      )

      setResult(transferResult)

      if (transferResult.success) {
        toast.success('Transfer complete!')
      } else {
        toast.error(transferResult.error || 'Transfer failed')
      }
    } catch (error) {
      console.error('Transfer error:', error)
      toast.error('Failed to transfer XLM')
      setResult({
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
      })
    } finally {
      setIsTransferring(false)
    }
  }

  const getStepIcon = (step: TransferStep) => {
    switch (step.status) {
      case 'success':
        return <Check size={16} className="text-success" />
      case 'error':
        return <AlertCircle size={16} className="text-error" />
      case 'running':
        return <Loader2 size={16} className="animate-spin text-soundness-blue" />
      default:
        return <div className="w-4 h-4 rounded-full bg-white/20" />
    }
  }

  return (
    <div className="space-y-6">
      {/* Info Box */}
      <div className="p-4 bg-muted rounded-xl text-sm text-muted-foreground">
        <p>
          Transfer XLM from your Falcon Smart Account. The transaction will be signed with your
          Falcon-512 key and verified on-chain before execution.
        </p>
      </div>

      {/* Transfer Form */}
      {canTransfer && (
        <div className="space-y-4">
          {/* Recipient */}
          <div>
            <label className="block text-sm text-muted-foreground mb-2">
              Recipient Address
            </label>
            <input
              type="text"
              value={recipient}
              onChange={(e) => setRecipient(e.target.value)}
              placeholder="G..."
              className="input-field font-mono text-sm"
            />
          </div>

          {/* Amount */}
          <div>
            <label className="block text-sm text-muted-foreground mb-2">
              Amount (XLM)
            </label>
            <div className="flex gap-3">
              <input
                type="number"
                value={amount}
                onChange={(e) => setAmount(e.target.value)}
                placeholder="1"
                min="0.0000001"
                step="0.1"
                className="input-field flex-1"
              />
              <button
                onClick={() => balance && setAmount(balance)}
                className="btn-secondary text-sm"
              >
                Max
              </button>
            </div>
            {balance && (
              <p className="text-xs text-muted-foreground mt-1">
                Available: {balance} XLM
              </p>
            )}
          </div>

          {/* Transfer Button */}
          <button
            onClick={handleTransfer}
            disabled={isTransferring || !isValidStellarAddress(recipient)}
            className="btn-primary w-full"
          >
            {isTransferring ? (
              <span className="flex items-center justify-center gap-2">
                <Loader2 size={18} className="animate-spin" />
                Transferring...
              </span>
            ) : (
              <span className="flex items-center justify-center gap-2">
                <Send size={18} />
                Transfer with Falcon Signature
              </span>
            )}
          </button>
        </div>
      )}

      {/* Progress Steps */}
      <AnimatePresence>
        {steps.length > 0 && (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            className="p-4 bg-muted rounded-xl space-y-2"
          >
            <p className="text-sm font-semibold text-white mb-3">Progress</p>
            {steps.map((step, index) => (
              <div
                key={index}
                className={cn(
                  'flex items-center gap-3 text-sm',
                  step.status === 'pending' && 'text-muted-foreground',
                  step.status === 'running' && 'text-white',
                  step.status === 'success' && 'text-success',
                  step.status === 'error' && 'text-error'
                )}
              >
                {getStepIcon(step)}
                <span>{step.name}</span>
                {step.message && (
                  <span className="text-xs text-muted-foreground ml-auto">
                    {step.message}
                  </span>
                )}
              </div>
            ))}
          </motion.div>
        )}
      </AnimatePresence>

      {/* Result Display */}
      <AnimatePresence>
        {result && !isTransferring && (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            className={cn(
              'p-6 rounded-xl border text-center',
              result.success
                ? 'bg-success/10 border-success'
                : 'bg-error/10 border-error'
            )}
          >
            {result.success ? (
              <>
                <motion.div
                  initial={{ scale: 0 }}
                  animate={{ scale: 1 }}
                  transition={{ type: 'spring', stiffness: 200 }}
                >
                  <Check size={48} className="mx-auto text-success mb-3" />
                </motion.div>
                <h3 className="text-xl font-bold text-success mb-2">
                  Transfer Complete!
                </h3>
                <p className="text-muted-foreground text-sm mb-4">
                  Successfully transferred {amount} XLM using Falcon-512 signature
                </p>
                {result.explorerUrl && (
                  <a
                    href={result.explorerUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-2 text-soundness-blue hover:text-soundness-blue-light transition-colors"
                  >
                    View on Explorer <ExternalLink size={16} />
                  </a>
                )}
                {result.transactionHash && (
                  <p className="text-xs font-mono text-muted-foreground mt-2">
                    {truncateAddress(result.transactionHash, 12, 12)}
                  </p>
                )}
              </>
            ) : (
              <>
                <AlertCircle size={48} className="mx-auto text-error mb-3" />
                <h3 className="text-xl font-bold text-error mb-2">
                  Transfer Failed
                </h3>
                <p className="text-muted-foreground text-sm">
                  {result.error}
                </p>
              </>
            )}
          </motion.div>
        )}
      </AnimatePresence>

      {/* Disabled State */}
      {!canTransfer && (
        <div className="p-4 bg-muted/50 rounded-xl text-center text-muted-foreground text-sm">
          Complete step 1 to transfer XLM
        </div>
      )}
    </div>
  )
}
