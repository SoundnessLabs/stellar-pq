import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Shield, ExternalLink, CheckCircle2, XCircle, Loader2 } from 'lucide-react'
import { cn, truncateHex } from '@/lib/utils'
import { verifySignatureOnChain, type VerificationResult } from '@/lib/stellar/verifier'
import { FALCON_VERIFIER_ID } from '@/lib/stellar/config'
import { verifyLocally, type FalconKeyPair } from '@/lib/falcon'
import { toast } from 'sonner'

interface OnChainVerifierProps {
  keys: FalconKeyPair | null
  seed: Uint8Array | null
  message: Uint8Array | null
  signature: Uint8Array | null
  isActive: boolean
}

type VerifyMode = 'local' | 'onchain'

export function OnChainVerifier({ keys, seed, message, signature, isActive: _isActive }: OnChainVerifierProps) {
  const [verifyMode, setVerifyMode] = useState<VerifyMode>('onchain')
  const [isVerifying, setIsVerifying] = useState(false)
  const [result, setResult] = useState<VerificationResult | null>(null)

  const canVerify = keys && seed && message && signature

  const handleVerify = async () => {
    if (!keys || !seed || !message || !signature) {
      toast.error('Please complete the previous steps first')
      return
    }

    setIsVerifying(true)
    setResult(null)

    try {
      let verifyResult: VerificationResult

      if (verifyMode === 'onchain') {
        verifyResult = await verifySignatureOnChain(keys.publicKey, message, signature)
      } else {
        // Local verification using WASM in browser
        const isValid = await verifyLocally(keys.publicKey, message, signature, seed)
        verifyResult = {
          success: true,
          result: isValid,
        }
      }

      setResult(verifyResult)

      if (verifyResult.success && verifyResult.result) {
        toast.success('Signature verified successfully!')
      } else if (verifyResult.success && !verifyResult.result) {
        toast.error('Signature verification failed')
      } else {
        toast.error(verifyResult.error || 'Verification error')
      }
    } catch (error) {
      console.error('Verification error:', error)
      setResult({
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
      })
      toast.error('Verification failed')
    } finally {
      setIsVerifying(false)
    }
  }

  return (
    <div className="space-y-6">
      {/* Contract Info */}
      <div className="p-4 bg-muted rounded-xl">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm text-muted-foreground mb-1">Contract Address (Testnet)</p>
            <p className="font-mono text-sm text-white">
              {truncateHex(FALCON_VERIFIER_ID, 8, 8)}
            </p>
          </div>
          <a
            href={`https://stellar.expert/explorer/testnet/contract/${FALCON_VERIFIER_ID}`}
            target="_blank"
            rel="noopener noreferrer"
            className="btn-secondary px-3 py-2 text-sm"
          >
            <ExternalLink size={16} className="mr-2 inline" />
            View
          </a>
        </div>
      </div>

      {/* Verify Mode Selection */}
      <div className="flex gap-3">
        <button
          onClick={() => setVerifyMode('onchain')}
          className={cn(
            'flex-1 px-4 py-3 rounded-xl text-sm font-medium transition-all border',
            verifyMode === 'onchain'
              ? 'bg-soundness-blue/20 border-soundness-blue text-white'
              : 'bg-white/5 border-white/10 text-muted-foreground hover:bg-white/10'
          )}
        >
          <div className="text-left">
            <div className="font-semibold mb-1">On-Chain</div>
            <div className="text-xs opacity-70">Submit to Soroban</div>
          </div>
        </button>
        <button
          onClick={() => setVerifyMode('local')}
          className={cn(
            'flex-1 px-4 py-3 rounded-xl text-sm font-medium transition-all border',
            verifyMode === 'local'
              ? 'bg-soundness-blue/20 border-soundness-blue text-white'
              : 'bg-white/5 border-white/10 text-muted-foreground hover:bg-white/10'
          )}
        >
          <div className="text-left">
            <div className="font-semibold mb-1">Local (Browser)</div>
            <div className="text-xs opacity-70">Free, no transaction</div>
          </div>
        </button>
      </div>

      {/* Verify Button */}
      <button
        onClick={handleVerify}
        disabled={!canVerify || isVerifying}
        className="btn-primary w-full"
      >
        {isVerifying ? (
          <span className="flex items-center justify-center gap-2">
            <Loader2 size={18} className="animate-spin" />
            {verifyMode === 'onchain' ? 'Submitting...' : 'Verifying...'}
          </span>
        ) : (
          <span className="flex items-center justify-center gap-2">
            <Shield size={18} />
            {verifyMode === 'onchain' ? 'Verify On-Chain' : 'Verify Locally'}
          </span>
        )}
      </button>

      {/* Result Display */}
      <AnimatePresence>
        {result && (
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            exit={{ opacity: 0, scale: 0.95 }}
            className={cn(
              'p-6 rounded-xl border-2 text-center',
              result.success && result.result
                ? 'bg-success/10 border-success'
                : 'bg-error/10 border-error'
            )}
          >
            {result.success && result.result ? (
              <>
                <motion.div
                  initial={{ scale: 0 }}
                  animate={{ scale: 1 }}
                  transition={{ type: 'spring', stiffness: 200 }}
                >
                  <CheckCircle2 size={64} className="mx-auto text-success mb-4" />
                </motion.div>
                <h3 className="text-2xl font-bold text-success mb-2">
                  Signature Valid
                </h3>
                <p className="text-muted-foreground text-sm">
                  The Falcon-512 signature was verified successfully on Soroban
                </p>
              </>
            ) : (
              <>
                <XCircle size={64} className="mx-auto text-error mb-4" />
                <h3 className="text-2xl font-bold text-error mb-2">
                  {result.success ? 'Signature Invalid' : 'Verification Error'}
                </h3>
                <p className="text-muted-foreground text-sm">
                  {result.error || 'The signature did not pass verification'}
                </p>
              </>
            )}

            {/* Transaction Details */}
            {result.transactionHash && (
              <div className="mt-4 pt-4 border-t border-white/10">
                <p className="text-sm text-muted-foreground mb-2">Transaction Hash</p>
                <a
                  href={result.explorerUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="font-mono text-sm text-soundness-blue hover:text-soundness-blue-light transition-colors"
                >
                  {truncateHex(result.transactionHash, 12, 12)}
                  <ExternalLink size={14} className="inline ml-2" />
                </a>
              </div>
            )}
          </motion.div>
        )}
      </AnimatePresence>

      {/* Disabled State */}
      {!canVerify && (
        <div className="p-4 bg-muted/50 rounded-xl text-center text-muted-foreground text-sm">
          Complete steps 1 and 2 to verify on-chain
        </div>
      )}
    </div>
  )
}
