/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // Soundness brand colors
        soundness: {
          blue: '#2400FF',
          'blue-light': '#4D33FF',
          'blue-dark': '#1A00CC',
        },
        // Dark theme
        background: '#000000',
        foreground: '#ffffff',
        muted: {
          DEFAULT: '#171717',
          foreground: '#a1a1aa',
        },
        card: {
          DEFAULT: '#0a0a0a',
          foreground: '#ffffff',
        },
        border: 'rgba(255, 255, 255, 0.1)',
        // Status colors
        success: '#22c55e',
        error: '#ef4444',
        warning: '#f59e0b',
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['Fragment Mono', 'JetBrains Mono', 'monospace'],
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'shimmer': 'shimmer 2s linear infinite',
      },
      keyframes: {
        shimmer: {
          '0%': { backgroundPosition: '-200% 0' },
          '100%': { backgroundPosition: '200% 0' },
        },
      },
      backgroundImage: {
        'gradient-radial': 'radial-gradient(var(--tw-gradient-stops))',
        'shimmer-gradient': 'linear-gradient(90deg, transparent, rgba(255,255,255,0.1), transparent)',
      },
    },
  },
  plugins: [],
}
