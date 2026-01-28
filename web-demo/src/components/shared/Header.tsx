import { motion } from 'framer-motion'
import { Github, ExternalLink, Home } from 'lucide-react'
import { Link, useLocation } from 'react-router-dom'

interface HeaderProps {
  title?: string
  subtitle?: string
  explorerUrl?: string
}

export function Header({
  title = 'Falcon-512 Demos',
  subtitle = 'Post-Quantum Cryptography on Stellar',
  explorerUrl,
}: HeaderProps) {
  const location = useLocation()
  const isHome = location.pathname === '/'

  return (
    <motion.header
      initial={{ opacity: 0, y: -20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5 }}
      className="w-full py-6 px-4 sm:px-6 lg:px-8"
    >
      <div className="max-w-5xl mx-auto flex items-center justify-between">
        {/* Logo and Title */}
        <div className="flex items-center gap-4">
          <Link to="/">
            <img
              src="/soundness_logo.png"
              alt="Soundness"
              className="h-10 w-10"
            />
          </Link>
          <div className="hidden sm:block">
            <h1 className="text-xl font-bold text-white">
              {title}
            </h1>
            <p className="text-sm text-muted-foreground">
              {subtitle}
            </p>
          </div>
        </div>

        {/* Links */}
        <div className="flex items-center gap-4">
          {!isHome && (
            <Link
              to="/"
              className="flex items-center gap-2 text-muted-foreground hover:text-white transition-colors"
            >
              <Home size={20} />
              <span className="hidden sm:inline">Home</span>
            </Link>
          )}
          <a
            href="https://github.com/soundness/falcon-rust"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-2 text-muted-foreground hover:text-white transition-colors"
          >
            <Github size={20} />
            <span className="hidden sm:inline">GitHub</span>
          </a>
          {explorerUrl && (
            <a
              href={explorerUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-2 text-muted-foreground hover:text-white transition-colors"
            >
              <ExternalLink size={20} />
              <span className="hidden sm:inline">Contract</span>
            </a>
          )}
        </div>
      </div>
    </motion.header>
  )
}
