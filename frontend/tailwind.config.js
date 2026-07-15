/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        ink: "#0b1120",
        panel: "#0f172a",
        panel2: "#16213a",
        edge: "#1e293b",
        accent: "#38bdf8",
        accent2: "#22d3ee",
        crit: "#ef4444",
        high: "#f97316",
        med: "#eab308",
        low: "#3b82f6",
        info: "#64748b",
      },
      fontFamily: {
        mono: ["ui-monospace", "SFMono-Regular", "Menlo", "monospace"],
      },
    },
  },
  plugins: [],
};
