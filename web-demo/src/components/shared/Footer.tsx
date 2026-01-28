import { motion } from 'framer-motion'

export function Footer() {
  return (
    <motion.footer
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.5, delay: 0.5 }}
      className="w-full py-8 px-4 sm:px-6 lg:px-8 mt-auto"
    >
      <div className="max-w-5xl mx-auto">
        <div className="border-t border-white/10 pt-8">
          <div className="flex flex-col sm:flex-row items-center justify-between gap-4">
            <div className="flex items-center gap-2 text-muted-foreground text-sm">
              <span>Built by</span>
              <a
                href="https://soundness.xyz"
                target="_blank"
                rel="noopener noreferrer"
                className="text-white hover:text-soundness-blue transition-colors font-medium"
              >
                Soundness
              </a>
              <span className="mx-2">|</span>
              <span>Post-Quantum Security for Web3</span>
            </div>

            <div className="flex items-center gap-6 text-sm">
              <a
                href="https://falcon-sign.info/"
                target="_blank"
                rel="noopener noreferrer"
                className="text-muted-foreground hover:text-white transition-colors"
              >
                Falcon Spec
              </a>
              <a
                href="https://stellar.org"
                target="_blank"
                rel="noopener noreferrer"
                className="text-muted-foreground hover:text-white transition-colors"
              >
                Stellar
              </a>
              <a
                href="https://soroban.stellar.org"
                target="_blank"
                rel="noopener noreferrer"
                className="text-muted-foreground hover:text-white transition-colors"
              >
                Soroban
              </a>
            </div>
          </div>

          <p className="text-center text-xs text-muted-foreground mt-6">
            This is a demo application on Stellar Testnet. Do not use with real funds.
          </p>
        </div>
      </div>
    </motion.footer>
  )
}
