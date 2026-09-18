/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          dark: '#0a0f1d',
          card: '#131b2e',
          border: '#1e293b',
          accent: '#00f0ff',
          danger: '#ff0055',
          warning: '#ffb700',
          success: '#00ff66'
        }
      }
    },
  },
  plugins: [],
}
