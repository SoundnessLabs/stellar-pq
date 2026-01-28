import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Key, Shuffle, Copy, Check, Eye, EyeOff } from 'lucide-react'
import { cn, bytesToHex, hexToBytes, copyToClipboard, truncateHex } from '@/lib/utils'
import { generateKeypair, generateRandomSeed, isValidSeed, type FalconKeyPair } from '@/lib/falcon'
import { toast } from 'sonner'

interface KeyGeneratorProps {
  onKeysGenerated: (keys: FalconKeyPair, seed: Uint8Array) => void
  isActive: boolean
}

export function KeyGenerator({ onKeysGenerated, isActive: _isActive }: KeyGeneratorProps) {
  const [seedMode, setSeedMode] = useState<'random' | 'custom'>('random')
  const [customSeed, setCustomSeed] = useState('')
  const [isGenerating, setIsGenerating] = useState(false)
  const [keys, setKeys] = useState<FalconKeyPair | null>(null)
  const [currentSeed, setCurrentSeed] = useState<Uint8Array | null>(null)
  const [showPrivateKey, setShowPrivateKey] = useState(false)
  const [copiedField, setCopiedField] = useState<string | null>(null)

  const handleCopy = async (text: string, field: string) => {
    const success = await copyToClipboard(text)
    if (success) {
      setCopiedField(field)
      toast.success('Copied to clipboard')
      setTimeout(() => setCopiedField(null), 2000)
    }
  }

  const handleGenerate = async () => {
    setIsGenerating(true)

    try {
      let seed: Uint8Array

      if (seedMode === 'custom') {
        if (!isValidSeed(customSeed)) {
          toast.error('Invalid seed. Must be 48 bytes (96 hex characters)')
          setIsGenerating(false)
          return
        }
        seed = hexToBytes(customSeed.startsWith('0x') ? customSeed.slice(2) : customSeed)
      } else {
        seed = generateRandomSeed()
      }

      const keypair = await generateKeypair(seed)
      setKeys(keypair)
      setCurrentSeed(seed)
      onKeysGenerated(keypair, seed)
      toast.success('Falcon-512 keypair generated')
    } catch (error) {
      console.error('Key generation failed:', error)
      toast.error('Failed to generate keypair')
    } finally {
      setIsGenerating(false)
    }
  }

  return (
    <div className="space-y-6">
      {/* Seed Mode Selection */}
      <div className="flex flex-wrap gap-3">
        <button
          onClick={() => setSeedMode('random')}
          className={cn(
            'px-4 py-2 rounded-lg text-sm font-medium transition-all',
            seedMode === 'random'
              ? 'bg-soundness-blue text-white'
              : 'bg-white/10 text-muted-foreground hover:bg-white/20'
          )}
        >
          <Shuffle size={16} className="inline mr-2" />
          Random Seed
        </button>
        <button
          onClick={() => setSeedMode('custom')}
          className={cn(
            'px-4 py-2 rounded-lg text-sm font-medium transition-all',
            seedMode === 'custom'
              ? 'bg-soundness-blue text-white'
              : 'bg-white/10 text-muted-foreground hover:bg-white/20'
          )}
        >
          <Key size={16} className="inline mr-2" />
          Custom Seed
        </button>
      </div>

      {/* Custom Seed Input */}
      <AnimatePresence>
        {seedMode === 'custom' && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            transition={{ duration: 0.2 }}
          >
            <label className="block text-sm text-muted-foreground mb-2">
              Enter 48-byte seed (96 hex characters):
            </label>
            <input
              type="text"
              value={customSeed}
              onChange={(e) => setCustomSeed(e.target.value)}
              placeholder="e.g., 061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1"
              className="input-field font-mono text-sm"
            />
          </motion.div>
        )}
      </AnimatePresence>

      {/* Generate Button */}
      <button
        onClick={handleGenerate}
        disabled={isGenerating || (seedMode === 'custom' && !isValidSeed(customSeed))}
        className="btn-primary w-full sm:w-auto"
      >
        {isGenerating ? (
          <span className="flex items-center justify-center gap-2">
            <motion.div
              animate={{ rotate: 360 }}
              transition={{ duration: 1, repeat: Infinity, ease: 'linear' }}
              className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full"
            />
            Generating...
          </span>
        ) : (
          <span className="flex items-center justify-center gap-2">
            <Key size={18} />
            Generate Keypair
          </span>
        )}
      </button>

      {/* Generated Keys Display */}
      <AnimatePresence>
        {keys && currentSeed && (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            className="space-y-4"
          >
            {/* Seed */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <label className="text-sm text-muted-foreground">Seed (48 bytes)</label>
                <button
                  onClick={() => handleCopy(bytesToHex(currentSeed), 'seed')}
                  className="text-muted-foreground hover:text-white transition-colors"
                >
                  {copiedField === 'seed' ? <Check size={16} /> : <Copy size={16} />}
                </button>
              </div>
              <div className="code-block text-xs text-green-400">
                {truncateHex(bytesToHex(currentSeed), 20, 20)}
              </div>
            </div>

            {/* Public Key */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <label className="text-sm text-muted-foreground">
                  Public Key ({keys.publicKey.length} bytes)
                </label>
                <button
                  onClick={() => handleCopy(bytesToHex(keys.publicKey), 'publicKey')}
                  className="text-muted-foreground hover:text-white transition-colors"
                >
                  {copiedField === 'publicKey' ? <Check size={16} /> : <Copy size={16} />}
                </button>
              </div>
              <div className="code-block text-xs text-blue-400">
                {truncateHex(bytesToHex(keys.publicKey), 24, 24)}
              </div>
            </div>

            {/* Private Key */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <label className="text-sm text-muted-foreground">
                  Private Key ({keys.privateKey.length} bytes)
                </label>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => setShowPrivateKey(!showPrivateKey)}
                    className="text-muted-foreground hover:text-white transition-colors"
                  >
                    {showPrivateKey ? <EyeOff size={16} /> : <Eye size={16} />}
                  </button>
                  <button
                    onClick={() => handleCopy(bytesToHex(keys.privateKey), 'privateKey')}
                    className="text-muted-foreground hover:text-white transition-colors"
                  >
                    {copiedField === 'privateKey' ? <Check size={16} /> : <Copy size={16} />}
                  </button>
                </div>
              </div>
              <div className="code-block text-xs text-red-400">
                {showPrivateKey
                  ? truncateHex(bytesToHex(keys.privateKey), 24, 24)
                  : '••••••••••••••••••••••••••••••••••••••••••••••••'}
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}
