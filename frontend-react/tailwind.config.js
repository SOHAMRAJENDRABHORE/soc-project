/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,jsx}",
  ],
  theme: {
    extend: {
      colors: {
        // SOC console palette — refined dark with burnt-orange accents
        ink: {
          950: '#0a0c14',
          900: '#0f1320',
          800: '#161b2c',
          700: '#1f2638',
          600: '#2a3349',
          500: '#3a4560',
          400: '#5b6786',
          300: '#8995b3',
          200: '#b8c0d8',
          100: '#dde2ef',
          50:  '#eef1f8',
        },
        amber: {
          // distinctive burnt-orange instead of generic blue
          500: '#ea580c',
          400: '#f97316',
          300: '#fb923c',
          200: '#fdba74',
        },
        crit: '#dc2626',
        warn: '#d97706',
        ok:   '#059669',
        info: '#0891b2',
      },
      fontFamily: {
        sans: ['"DM Sans"', 'system-ui', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'ui-monospace', 'monospace'],
        display: ['"Space Grotesk"', 'system-ui', 'sans-serif'],
      },
      animation: {
        'pulse-dot': 'pulse-dot 2s ease-in-out infinite',
        'shimmer': 'shimmer 2.5s linear infinite',
        'fade-in': 'fade-in 240ms ease-out',
        'slide-up': 'slide-up 320ms cubic-bezier(.16,1,.3,1)',
      },
      keyframes: {
        'pulse-dot': {
          '0%, 100%': { opacity: '1', transform: 'scale(1)' },
          '50%': { opacity: '0.5', transform: 'scale(0.85)' },
        },
        'shimmer': {
          '0%': { backgroundPosition: '-200% 0' },
          '100%': { backgroundPosition: '200% 0' },
        },
        'fade-in': {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        'slide-up': {
          '0%': { opacity: '0', transform: 'translateY(8px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
      },
      backgroundImage: {
        'grid-fade': 'radial-gradient(ellipse 60% 40% at 50% 0%, rgba(234,88,12,0.08), transparent 60%)',
        'scanlines': 'repeating-linear-gradient(0deg, rgba(255,255,255,0.015) 0px, rgba(255,255,255,0.015) 1px, transparent 1px, transparent 3px)',
      },
    },
  },
  plugins: [],
}
