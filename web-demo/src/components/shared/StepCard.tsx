import { motion } from 'framer-motion'
import { cn } from '@/lib/utils'
import { Check } from 'lucide-react'

interface StepCardProps {
  stepNumber: number
  title: string
  description: string
  children: React.ReactNode
  isActive?: boolean
  isComplete?: boolean
  className?: string
}

export function StepCard({
  stepNumber,
  title,
  description,
  children,
  isActive = false,
  isComplete = false,
  className,
}: StepCardProps) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5, delay: stepNumber * 0.1 }}
      className={cn(
        'glass-card gradient-border p-6 sm:p-8',
        isActive && 'ring-2 ring-soundness-blue/50',
        className
      )}
    >
      {/* Header */}
      <div className="flex items-start gap-4 mb-6">
        {/* Step Badge */}
        <div
          className={cn(
            'flex-shrink-0 w-10 h-10 rounded-full flex items-center justify-center font-bold text-sm transition-all duration-300',
            isComplete
              ? 'bg-success text-white'
              : isActive
              ? 'bg-soundness-blue text-white'
              : 'bg-white/10 text-muted-foreground'
          )}
        >
          {isComplete ? <Check size={20} /> : stepNumber}
        </div>

        {/* Title and Description */}
        <div className="flex-1 min-w-0">
          <h2 className="text-xl font-semibold text-white mb-1">{title}</h2>
          <p className="text-sm text-muted-foreground">{description}</p>
        </div>
      </div>

      {/* Content */}
      <div className="pl-0 sm:pl-14">{children}</div>
    </motion.div>
  )
}
