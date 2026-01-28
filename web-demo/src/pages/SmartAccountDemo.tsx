import { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { Toaster } from 'sonner'
import { Header } from '@/components/shared/Header'
import { Footer } from '@/components/shared/Footer'
import { StepCard } from '@/components/shared/StepCard'
import { FundAccount } from '@/components/smart-account/FundAccount'
import { TransferXLM } from '@/components/smart-account/TransferXLM'
import { initFalcon, generateKeypair } from '@/lib/falcon'
import { PRE_DEPLOYED_SEED, PRE_DEPLOYED_SMART_ACCOUNT } from '@/lib/stellar/config'
import { hexToBytes } from '@/lib/utils'

export function SmartAccountDemo() {
  const [isInitialized, setIsInitialized] = useState(false)
  const [activeStep, setActiveStep] = useState(1)

  // State
  const [seed, setSeed] = useState<Uint8Array | null>(null)
  const [contractId, setContractId] = useState<string | null>(null)
  const [balance, setBalance] = useState<string | null>(null)

  // Initialize Falcon module and auto-load demo keypair and contract
  useEffect(() => {
    const initialize = async () => {
      await initFalcon()

      // Auto-load the demo keypair that matches the pre-deployed contract
      try {
        const demoSeed = hexToBytes(PRE_DEPLOYED_SEED)
        await generateKeypair(demoSeed)
        setSeed(demoSeed)
        // Use pre-deployed contract
        setContractId(PRE_DEPLOYED_SMART_ACCOUNT)
      } catch (error) {
        console.error('Failed to initialize:', error)
      }

      setIsInitialized(true)
    }

    initialize()
  }, [])

  const handleAccountFunded = (newBalance: string) => {
    setBalance(newBalance)
    setActiveStep(2)
  }

  return (
    <div className="min-h-screen flex flex-col bg-background">
      {/* Toast notifications */}
      <Toaster
        position="top-right"
        toastOptions={{
          style: {
            background: '#171717',
            border: '1px solid rgba(255, 255, 255, 0.1)',
            color: '#fff',
          },
        }}
      />

      {/* Background gradient */}
      <div className="fixed inset-0 pointer-events-none">
        <div className="absolute top-0 left-1/4 w-96 h-96 bg-soundness-blue/20 rounded-full blur-[128px]" />
        <div className="absolute bottom-0 right-1/4 w-96 h-96 bg-purple-500/10 rounded-full blur-[128px]" />
      </div>

      <Header
        title="Falcon Smart Account"
        subtitle="Post-Quantum Account Abstraction"
        explorerUrl={contractId ? `https://stellar.expert/explorer/testnet/contract/${contractId}` : undefined}
      />

      <main className="flex-1 px-4 sm:px-6 lg:px-8 py-8 relative z-10">
        <div className="max-w-3xl mx-auto space-y-6">
          {/* Hero Section */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
            className="text-center mb-12"
          >
            <h1 className="text-4xl sm:text-5xl font-bold text-white mb-4">
              Post-Quantum
              <br />
              <span className="text-gradient-blue">Smart Accounts</span>
            </h1>
            <p className="text-lg text-muted-foreground max-w-2xl mx-auto">
              Fund a Falcon-512 smart account and transfer XLM using
              post-quantum signatures on Stellar Testnet.
            </p>
          </motion.div>

          {/* Loading State */}
          {!isInitialized && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="text-center py-12"
            >
              <motion.div
                animate={{ rotate: 360 }}
                transition={{ duration: 1, repeat: Infinity, ease: 'linear' }}
                className="w-12 h-12 border-4 border-soundness-blue/30 border-t-soundness-blue rounded-full mx-auto mb-4"
              />
              <p className="text-muted-foreground">Initializing Falcon module...</p>
            </motion.div>
          )}

          {/* Steps */}
          {isInitialized && (
            <>
              {/* Step 1: Fund Account */}
              <StepCard
                stepNumber={1}
                title="Fund Account"
                description="Add XLM to the smart account from our testnet faucet"
                isActive={activeStep === 1}
                isComplete={balance !== null && parseFloat(balance) > 0}
              >
                <FundAccount
                  contractId={contractId}
                  onFunded={handleAccountFunded}
                  isActive={activeStep === 1}
                />
              </StepCard>

              {/* Step 2: Transfer XLM */}
              <StepCard
                stepNumber={2}
                title="Transfer XLM"
                description="Send XLM from the smart account using Falcon signature"
                isActive={activeStep === 2}
                isComplete={false}
              >
                <TransferXLM
                  contractId={contractId}
                  seed={seed}
                  balance={balance}
                  isActive={activeStep === 2}
                />
              </StepCard>
            </>
          )}
        </div>
      </main>

      <Footer />
    </div>
  )
}
