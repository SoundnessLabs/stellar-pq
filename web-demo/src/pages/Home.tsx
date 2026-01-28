import { motion } from 'framer-motion'
import { Link } from 'react-router-dom'
import { Shield, Wallet, ArrowRight } from 'lucide-react'
import { Header } from '@/components/shared/Header'
import { Footer } from '@/components/shared/Footer'

export function Home() {
  return (
    <div className="min-h-screen flex flex-col bg-background">
      {/* Background gradient */}
      <div className="fixed inset-0 pointer-events-none">
        <div className="absolute top-0 left-1/4 w-96 h-96 bg-soundness-blue/20 rounded-full blur-[128px]" />
        <div className="absolute bottom-0 right-1/4 w-96 h-96 bg-purple-500/10 rounded-full blur-[128px]" />
      </div>

      <Header />

      <main className="flex-1 px-4 sm:px-6 lg:px-8 py-8 relative z-10">
        <div className="max-w-4xl mx-auto">
          {/* Hero Section */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
            className="text-center mb-16"
          >
            <h1 className="text-4xl sm:text-5xl lg:text-6xl font-bold text-white mb-6">
              Post-Quantum Cryptography
              <br />
              <span className="text-gradient-blue">on Stellar</span>
            </h1>
            <p className="text-lg sm:text-xl text-muted-foreground max-w-2xl mx-auto">
              Experience Falcon-512 post-quantum signatures on the Stellar blockchain.
              Generate keys, sign messages, and execute smart account transactions.
            </p>
          </motion.div>

          {/* Demo Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Verifier Demo Card */}
            <motion.div
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.5, delay: 0.2 }}
            >
              <Link
                to="/verifier"
                className="block glass-card gradient-border p-8 hover:ring-2 hover:ring-soundness-blue/50 transition-all group"
              >
                <div className="flex items-start justify-between mb-6">
                  <div className="p-3 bg-soundness-blue/20 rounded-xl">
                    <Shield size={32} className="text-soundness-blue" />
                  </div>
                  <ArrowRight
                    size={24}
                    className="text-muted-foreground group-hover:text-white group-hover:translate-x-1 transition-all"
                  />
                </div>
                <h2 className="text-2xl font-bold text-white mb-3">
                  Signature Verifier
                </h2>
                <p className="text-muted-foreground">
                  Generate Falcon-512 keypairs, sign messages in your browser, and verify
                  signatures on-chain using Soroban smart contracts.
                </p>
              </Link>
            </motion.div>

            {/* Smart Account Demo Card */}
            <motion.div
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.5, delay: 0.3 }}
            >
              <Link
                to="/smart-account"
                className="block glass-card gradient-border p-8 hover:ring-2 hover:ring-soundness-blue/50 transition-all group"
              >
                <div className="flex items-start justify-between mb-6">
                  <div className="p-3 bg-success/20 rounded-xl">
                    <Wallet size={32} className="text-success" />
                  </div>
                  <ArrowRight
                    size={24}
                    className="text-muted-foreground group-hover:text-white group-hover:translate-x-1 transition-all"
                  />
                </div>
                <h2 className="text-2xl font-bold text-white mb-3">
                  Smart Account
                </h2>
                <p className="text-muted-foreground">
                  Fund a Falcon-512 smart account and transfer XLM using post-quantum
                  signatures for account abstraction on Stellar.
                </p>
              </Link>
            </motion.div>
          </div>
        </div>
      </main>

      <Footer />
    </div>
  )
}
