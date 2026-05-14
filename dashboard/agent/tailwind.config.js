/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      fontFamily: {
        mono: ['"JetBrains Mono"', '"Fira Code"', 'monospace'],
        sans: ['"DM Sans"', 'sans-serif'],
      },
      colors: {
        void:    '#080b0f',
        surface: '#0e1318',
        panel:   '#131920',
        border:  '#1e2730',
        muted:   '#2a3540',
        dim:     '#4a5a68',
        text:    '#c8d8e8',
        bright:  '#e8f4ff',
        cyan:    '#00d4ff',
        green:   '#00ff9d',
        yellow:  '#ffcc00',
        orange:  '#ff8c42',
        red:     '#ff3b5c',
        purple:  '#9b5de5',
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4,0,0.6,1) infinite',
        'blink': 'blink 1s step-end infinite',
        'slide-in': 'slideIn 0.2s ease-out',
        'fade-in': 'fadeIn 0.3s ease-out',
      },
      keyframes: {
        blink: { '0%,100%': { opacity: '1' }, '50%': { opacity: '0' } },
        slideIn: { from: { transform: 'translateY(-8px)', opacity: '0' }, to: { transform: 'translateY(0)', opacity: '1' } },
        fadeIn: { from: { opacity: '0' }, to: { opacity: '1' } },
      },
    },
  },
  plugins: [],
}