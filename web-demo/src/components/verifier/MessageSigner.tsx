import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { PenTool, Copy, Check } from 'lucide-react'
import { cn, bytesToHex, copyToClipboard, truncateHex } from '@/lib/utils'
import { sign, type FalconKeyPair } from '@/lib/falcon'
import { toast } from 'sonner'

interface MessageSignerProps {
  keys: FalconKeyPair | null
  seed: Uint8Array | null
  onMessageSigned: (message: Uint8Array, signature: Uint8Array) => void
  isActive: boolean
}

export function MessageSigner({ keys, seed, onMessageSigned, isActive: _isActive }: MessageSignerProps) {
  const [message, setMessage] = useState('')
  const [isSigning, setIsSigning] = useState(false)
  const [signature, setSignature] = useState<Uint8Array | null>(null)
  const [signedMessage, setSignedMessage] = useState<Uint8Array | null>(null)
  const [copiedField, setCopiedField] = useState<string | null>(null)

  const handleCopy = async (text: string, field: string) => {
    const success = await copyToClipboard(text)
    if (success) {
      setCopiedField(field)
      toast.success('Copied to clipboard')
      setTimeout(() => setCopiedField(null), 2000)
    }
  }

  const handleSign = async () => {
    if (!keys || !seed) {
      toast.error('Please generate a keypair first')
      return
    }

    if (!message.trim()) {
      toast.error('Please enter a message to sign')
      return
    }

    setIsSigning(true)

    try {
      const messageBytes = new TextEncoder().encode(message)

      // Sign using the real Falcon-512 WASM module
      // IMPORTANT: Must use the same seed that generated the keypair
      const signResult = await sign(keys.privateKey, messageBytes, seed)
      const sig = signResult.signature

      setSignature(sig)
      setSignedMessage(messageBytes)
      onMessageSigned(messageBytes, sig)
      toast.success(`Message signed (${sig.length} bytes)`)
    } catch (error) {
      console.error('Signing failed:', error)
      toast.error('Failed to sign message')
    } finally {
      setIsSigning(false)
    }
  }

  return (
    <div className="space-y-6">
      {/* Message Input */}
      <div>
        <label className="block text-sm text-muted-foreground mb-2">
          Message to Sign
        </label>
        <textarea
          value={message}
          onChange={(e) => setMessage(e.target.value)}
          placeholder="Enter your message here..."
          disabled={!keys}
          className={cn(
            'input-field min-h-[100px] resize-none',
            !keys && 'opacity-50 cursor-not-allowed'
          )}
        />
      </div>

      {/* Sign Button */}
      <button
        onClick={handleSign}
        disabled={!keys || isSigning || !message.trim()}
        className="btn-primary w-full sm:w-auto"
      >
        {isSigning ? (
          <span className="flex items-center justify-center gap-2">
            <motion.div
              animate={{ rotate: 360 }}
              transition={{ duration: 1, repeat: Infinity, ease: 'linear' }}
              className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full"
            />
            Signing...
          </span>
        ) : (
          <span className="flex items-center justify-center gap-2">
            <PenTool size={18} />
            Sign Message
          </span>
        )}
      </button>

      {/* Signature Display */}
      <AnimatePresence>
        {signature && signedMessage && (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            className="space-y-4"
          >
            {/* Message Hex */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <label className="text-sm text-muted-foreground">
                  Message ({signedMessage.length} bytes)
                </label>
                <button
                  onClick={() => handleCopy(bytesToHex(signedMessage), 'message')}
                  className="text-muted-foreground hover:text-white transition-colors"
                >
                  {copiedField === 'message' ? <Check size={16} /> : <Copy size={16} />}
                </button>
              </div>
              <div className="code-block text-xs text-yellow-400">
                {truncateHex(bytesToHex(signedMessage), 24, 24)}
              </div>
            </div>

            {/* Signature */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <label className="text-sm text-muted-foreground">
                  Signature ({signature.length} bytes)
                </label>
                <button
                  onClick={() => handleCopy(bytesToHex(signature), 'signature')}
                  className="text-muted-foreground hover:text-white transition-colors"
                >
                  {copiedField === 'signature' ? <Check size={16} /> : <Copy size={16} />}
                </button>
              </div>
              <div className="code-block text-xs text-purple-400">
                {truncateHex(bytesToHex(signature), 24, 24)}
              </div>
            </div>

            {/* Signature Format Info */}
            <div className="p-3 bg-muted rounded-lg text-xs text-muted-foreground">
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <span className="text-white">Format:</span> Compressed (0x39)
                </div>
                <div>
                  <span className="text-white">Algorithm:</span> Falcon-512
                </div>
                <div>
                  <span className="text-white">Nonce:</span> 40 bytes
                </div>
                <div>
                  <span className="text-white">Security:</span> 128-bit PQ
                </div>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Disabled State */}
      {!keys && (
        <div className="p-4 bg-muted/50 rounded-xl text-center text-muted-foreground text-sm">
          Generate a keypair first to sign messages
        </div>
      )}
    </div>
  )
}
