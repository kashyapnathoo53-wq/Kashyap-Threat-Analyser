import React, { useState, useEffect } from 'react';
import { cyberAudio } from '../utils/cyberAudio';
import { 
  Palette, X, Check, Sparkles, RefreshCw, Sliders
} from 'lucide-react';

export type ThemeId = 'cyan' | 'cobalt' | 'emerald' | 'violet' | 'crimson' | 'carbon' | 'ironman';

export interface ThemeOption {
  id: ThemeId;
  name: string;
  subtitle: string;
  primaryColor: string;
  secondaryColor: string;
  glowColor: string;
  previewClass: string;
}

export const THEME_OPTIONS: ThemeOption[] = [
  {
    id: 'cyan',
    name: 'Arc Cyan (Default)',
    subtitle: 'Zero Orange • Electric Arc Blue & Deep Space Navy',
    primaryColor: '#06b6d4',
    secondaryColor: '#00f2fe',
    glowColor: 'rgba(6, 182, 212, 0.45)',
    previewClass: 'from-cyan-900/60 to-slate-950 border-cyan-500/50'
  },
  {
    id: 'cobalt',
    name: 'Tactical Cobalt',
    subtitle: 'Deep Defense Blue & Royal Cyber Navy',
    primaryColor: '#3b82f6',
    secondaryColor: '#60a5fa',
    glowColor: 'rgba(59, 130, 246, 0.45)',
    previewClass: 'from-blue-900/60 to-slate-950 border-blue-500/50'
  },
  {
    id: 'emerald',
    name: 'Matrix Emerald',
    subtitle: 'Terminal Hacker Green & Midnight Black',
    primaryColor: '#10b981',
    secondaryColor: '#34d399',
    glowColor: 'rgba(16, 185, 129, 0.45)',
    previewClass: 'from-emerald-900/60 to-slate-950 border-emerald-500/50'
  },
  {
    id: 'violet',
    name: 'Neon Violet',
    subtitle: 'Synthwave Cyberpunk Violet & Dark Abyss',
    primaryColor: '#a855f7',
    secondaryColor: '#c084fc',
    glowColor: 'rgba(168, 85, 247, 0.45)',
    previewClass: 'from-purple-900/60 to-slate-950 border-purple-500/50'
  },
  {
    id: 'crimson',
    name: 'Stealth Crimson',
    subtitle: 'High-Alert Threat Red & Dark Burgundy',
    primaryColor: '#ef4444',
    secondaryColor: '#f87171',
    glowColor: 'rgba(239, 68, 68, 0.45)',
    previewClass: 'from-red-900/60 to-slate-950 border-red-500/50'
  },
  {
    id: 'carbon',
    name: 'Stealth Carbon',
    subtitle: 'Minimalist Titanium Slate & Platinum Silver',
    primaryColor: '#94a3b8',
    secondaryColor: '#cbd5e1',
    glowColor: 'rgba(148, 163, 184, 0.35)',
    previewClass: 'from-slate-800/60 to-slate-950 border-slate-500/50'
  },
  {
    id: 'ironman',
    name: 'Stark Armor',
    subtitle: 'Hotrod Crimson with Arc Reactor Cyan Core',
    primaryColor: '#00f2fe',
    secondaryColor: '#ef4444',
    glowColor: 'rgba(0, 242, 254, 0.45)',
    previewClass: 'from-red-950/70 to-slate-950 border-red-500/50'
  }
];

const CUSTOM_COLOR_PRESETS = [
  { name: 'Arc Blue', hex: '#00f2fe' },
  { name: 'Sky Cyan', hex: '#06b6d4' },
  { name: 'Cobalt', hex: '#2563eb' },
  { name: 'Indigo', hex: '#6366f1' },
  { name: 'Electric Violet', hex: '#8b5cf6' },
  { name: 'Neon Purple', hex: '#a855f7' },
  { name: 'Fuchsia', hex: '#d946ef' },
  { name: 'Emerald', hex: '#10b981' },
  { name: 'Teal Mint', hex: '#14b8a6' },
  { name: 'Crimson', hex: '#ef4444' },
  { name: 'Titanium', hex: '#94a3b8' },
  { name: 'Ice White', hex: '#e2e8f0' }
];

interface ThemeSelectorModalProps {
  currentTheme: ThemeId;
  isOpen: boolean;
  onClose: () => void;
  onSelectTheme: (theme: ThemeId) => void;
  onApplyCustomColor: (hex: string) => void;
  activeCustomColor: string | null;
  onResetDefault: () => void;
}

export const ThemeSelectorModal: React.FC<ThemeSelectorModalProps> = ({
  currentTheme,
  isOpen,
  onClose,
  onSelectTheme,
  onApplyCustomColor,
  activeCustomColor,
  onResetDefault
}) => {
  const [customHex, setCustomHex] = useState<string>(activeCustomColor || '#06b6d4');

  useEffect(() => {
    if (activeCustomColor) setCustomHex(activeCustomColor);
  }, [activeCustomColor]);

  if (!isOpen) return null;

  const handleSelectPreset = (tId: ThemeId) => {
    cyberAudio.playClick();
    onSelectTheme(tId);
  };

  const handleCustomColorChange = (hex: string) => {
    setCustomHex(hex);
    onApplyCustomColor(hex);
    cyberAudio.playClick();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/85 backdrop-blur-md animate-fadeIn">
      <div 
        className="w-full max-w-2xl bg-[#030914]/95 border border-cyan-500/40 rounded-3xl shadow-2xl shadow-cyan-950/80 overflow-hidden flex flex-col max-h-[90vh] animate-scaleUp hud-corner"
        style={{
          borderColor: activeCustomColor ? `${activeCustomColor}60` : undefined,
          boxShadow: activeCustomColor ? `0 25px 60px -15px ${activeCustomColor}40` : undefined
        }}
      >
        {/* Header */}
        <div className="p-5 border-b border-cyan-500/20 flex items-center justify-between bg-gradient-to-r from-cyan-950/40 via-transparent to-transparent">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-2xl bg-cyan-500/10 border border-cyan-500/40 flex items-center justify-center text-cyan-400">
              <Palette className="w-5 h-5 stroke-[2.5]" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-base font-black text-white tracking-wide">
                  Display &amp; Holographic Theme Studio
                </h3>
                <span className="px-2 py-0.5 rounded-full text-[9px] font-mono font-black bg-cyan-950/80 text-cyan-300 border border-cyan-500/40">
                  REAL-TIME REACTIVE
                </span>
              </div>
              <p className="text-xs text-slate-400">
                Personalize your cyber defense workspace theme or apply any custom accent color.
              </p>
            </div>
          </div>

          <button 
            type="button"
            onClick={onClose}
            className="p-2 rounded-xl text-slate-400 hover:text-white hover:bg-white/[0.06] transition cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content Body */}
        <div className="p-6 space-y-6 overflow-y-auto">
          {/* Preset Themes Grid */}
          <div>
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs font-mono font-bold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
                Curated Theme Palettes
              </span>
              <span className="text-[11px] font-mono text-cyan-400">
                Click any palette to switch instantly
              </span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              {THEME_OPTIONS.map((theme) => {
                const isSelected = currentTheme === theme.id && !activeCustomColor;
                return (
                  <button
                    key={theme.id}
                    type="button"
                    onClick={() => handleSelectPreset(theme.id)}
                    className={`p-3.5 rounded-2xl border text-left transition-all duration-200 cursor-pointer group flex items-start gap-3 relative overflow-hidden ${
                      isSelected 
                        ? 'bg-slate-900/90 border-white/40 ring-2 shadow-lg scale-[1.01]' 
                        : 'bg-slate-950/60 border-white/[0.08] hover:border-white/20 hover:bg-slate-900/40'
                    }`}
                    style={{
                      borderColor: isSelected ? theme.primaryColor : undefined,
                      boxShadow: isSelected ? `0 10px 25px -5px ${theme.glowColor}` : undefined
                    }}
                  >
                    {/* Swatch circle */}
                    <div 
                      className="w-10 h-10 rounded-xl shrink-0 flex items-center justify-center border shadow-md relative mt-0.5"
                      style={{
                        background: `linear-gradient(135deg, ${theme.primaryColor}, ${theme.secondaryColor})`,
                        borderColor: 'rgba(255,255,255,0.2)'
                      }}
                    >
                      {isSelected ? (
                        <Check className="w-5 h-5 text-slate-950 stroke-[3]" />
                      ) : (
                        <span className="w-2.5 h-2.5 rounded-full bg-slate-950/60" />
                      )}
                    </div>

                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-1.5">
                        <span className="text-xs font-bold text-white tracking-wide truncate">
                          {theme.name}
                        </span>
                        {isSelected && (
                          <span 
                            className="px-1.5 py-0.2 rounded text-[9px] font-mono font-black text-slate-950 uppercase"
                            style={{ backgroundColor: theme.primaryColor }}
                          >
                            Active
                          </span>
                        )}
                      </div>
                      <p className="text-[11px] text-slate-400 mt-0.5 line-clamp-1">
                        {theme.subtitle}
                      </p>
                      <div className="flex items-center gap-2 mt-2">
                        <span className="w-3 h-3 rounded-full" style={{ backgroundColor: theme.primaryColor }} />
                        <span className="w-3 h-3 rounded-full" style={{ backgroundColor: theme.secondaryColor }} />
                        <span className="text-[10px] font-mono text-slate-500 uppercase">
                          {theme.primaryColor}
                        </span>
                      </div>
                    </div>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Custom Accent Color Picker */}
          <div className="p-4 rounded-2xl bg-slate-950/80 border border-white/[0.08] space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <Sliders className="w-4 h-4 text-cyan-400" />
                <span className="text-xs font-bold text-white">Custom Accent Color Override</span>
              </div>
              <span className="text-[11px] font-mono text-slate-400">
                Choose any precise HEX hue for borders, glowing effects &amp; lasers
              </span>
            </div>

            {/* Quick chips */}
            <div className="flex flex-wrap items-center gap-2">
              {CUSTOM_COLOR_PRESETS.map((preset) => (
                <button
                  key={preset.hex}
                  type="button"
                  onClick={() => handleCustomColorChange(preset.hex)}
                  className={`px-2.5 py-1 rounded-xl text-xs font-mono font-bold flex items-center gap-1.5 transition cursor-pointer border ${
                    activeCustomColor === preset.hex 
                      ? 'border-white text-white shadow-md' 
                      : 'border-white/[0.08] bg-slate-900/60 text-slate-300 hover:border-white/30'
                  }`}
                >
                  <span className="w-2.5 h-2.5 rounded-full shrink-0" style={{ backgroundColor: preset.hex }} />
                  <span>{preset.name}</span>
                </button>
              ))}
            </div>

            {/* Manual Color Picker Input */}
            <div className="flex items-center gap-3 pt-1">
              <label className="flex items-center gap-2 px-3 py-2 rounded-xl bg-slate-900 border border-white/10 hover:border-white/25 cursor-pointer text-xs font-mono text-white transition">
                <input 
                  type="color" 
                  value={customHex} 
                  onChange={(e) => handleCustomColorChange(e.target.value)}
                  className="w-6 h-6 rounded cursor-pointer border-0 p-0 bg-transparent"
                />
                <span>Pick Custom Hex: <strong className="font-mono text-cyan-300 uppercase">{customHex}</strong></span>
              </label>

              <button
                type="button"
                onClick={onResetDefault}
                className="flex items-center gap-1.5 px-3 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-white border border-white/10 text-xs font-bold transition cursor-pointer ml-auto"
                title="Reset to default clean Arc Cyan"
              >
                <RefreshCw className="w-3.5 h-3.5" />
                <span>Reset to Default (Arc Cyan)</span>
              </button>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-cyan-500/20 bg-slate-950/60 flex items-center justify-between">
          <div className="text-xs text-slate-400 flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
            <span>Theme preferences are saved automatically across sessions.</span>
          </div>

          <button
            type="button"
            onClick={onClose}
            className="px-5 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-black text-xs transition cursor-pointer shadow-lg shadow-cyan-950/60"
          >
            Apply &amp; Done
          </button>
        </div>
      </div>
    </div>
  );
};
