import React, { useState, useEffect, useRef } from 'react';
import { Terminal, Play, Pause, Trash2, ChevronDown, ChevronUp, Shield, Activity } from 'lucide-react';
import { cyberAudio } from '../utils/cyberAudio';

interface LogEntry {
  id: number;
  time: string;
  source: 'KERNEL' | 'MEMORY' | 'NETWORK' | 'YARA' | 'EDR';
  level: 'INFO' | 'WARN' | 'CRIT';
  message: string;
}

export const LiveTelemetryTerminal: React.FC = () => {
  const [isOpen, setIsOpen] = useState(false);
  const [isPaused, setIsPaused] = useState(false);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const scrollRef = useRef<HTMLDivElement | null>(null);

  const sampleEvents = [
    { source: 'KERNEL' as const, level: 'INFO' as const, message: 'ntdll.dll!NtQueryInformationProcess: ProcessInformationClass=0x07 (ProcessDebugPort) -> STATUS_SUCCESS' },
    { source: 'MEMORY' as const, level: 'CRIT' as const, message: 'kernel32.dll!VirtualAllocEx: flAllocationType=MEM_COMMIT|MEM_RESERVE flProtect=PAGE_EXECUTE_READWRITE [Base=0x00780000 Size=4096]' },
    { source: 'NETWORK' as const, level: 'CRIT' as const, message: 'WS2_32.dll!connect: RemoteSocket=185.220.101.4:443 Proto=TCP SYN_SENT [Payload=1,420 bytes encrypted]' },
    { source: 'YARA' as const, level: 'WARN' as const, message: 'yara_engine::eval: StringMatch rule="Ransomware_ShadowCopy" offset=0x00000412 matched="vssadmin.exe delete shadows"' },
    { source: 'EDR' as const, level: 'INFO' as const, message: 'sys_sentinel::interceptor: API hook verified intact on ntdll.dll!LdrLoadDll' },
    { source: 'KERNEL' as const, level: 'CRIT' as const, message: 'ntoskrnl!NtCreateThreadEx: Remote target PID=5120 (cmd.exe) -> ThreadId=0x14C0' },
    { source: 'MEMORY' as const, level: 'WARN' as const, message: 'entropy_scanner: Section .text chunk [0x1000-0x3000] calculated entropy = 7.641 (UPX compressed)' },
    { source: 'NETWORK' as const, level: 'INFO' as const, message: 'dns_resolver: Query A records for dropzone-exfil.xyz -> 194.165.16.42 TTL=300' }
  ];

  useEffect(() => {
    // Populate initial logs
    const initial: LogEntry[] = sampleEvents.slice(0, 4).map((e, idx) => ({
      id: Date.now() - (4 - idx) * 1000,
      time: new Date(Date.now() - (4 - idx) * 1000).toTimeString().split(' ')[0] + '.' + String(Math.floor(Math.random() * 900 + 100)),
      ...e
    }));
    setLogs(initial);

    const interval = setInterval(() => {
      if (isPaused) return;
      const pick = sampleEvents[Math.floor(Math.random() * sampleEvents.length)];
      const newEntry: LogEntry = {
        id: Date.now(),
        time: new Date().toTimeString().split(' ')[0] + '.' + String(Math.floor(Math.random() * 900 + 100)),
        ...pick
      };

      setLogs(prev => [...prev.slice(-40), newEntry]);
    }, 1800);

    return () => clearInterval(interval);
  }, [isPaused]);

  useEffect(() => {
    if (!isPaused && scrollRef.current && isOpen) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [logs, isOpen, isPaused]);

  const toggleOpen = () => {
    setIsOpen(prev => !prev);
    cyberAudio.playClick();
  };

  const togglePause = (e: React.MouseEvent) => {
    e.stopPropagation();
    setIsPaused(prev => !prev);
    cyberAudio.playClick();
  };

  const clearLogs = (e: React.MouseEvent) => {
    e.stopPropagation();
    setLogs([]);
    cyberAudio.playClick();
  };

  return (
    <div className="glass-panel border-t border-cyan-900/50 shadow-2xl relative z-30 transition-all duration-300">
      {/* Dock Bar */}
      <div 
        onClick={toggleOpen}
        className="px-4 py-2.5 flex items-center justify-between cursor-pointer hover:bg-cyan-950/30 transition select-none"
      >
        <div className="flex items-center gap-2.5 text-xs font-mono">
          <span className="relative flex h-2 w-2">
            <span className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${isPaused ? 'bg-amber-400' : 'bg-emerald-400'}`} />
            <span className={`relative inline-flex rounded-full h-2 w-2 ${isPaused ? 'bg-amber-400' : 'bg-emerald-400'}`} />
          </span>
          <Terminal className="w-4 h-4 text-cyan-400" />
          <span className="font-extrabold text-white">LIVE FORENSIC TELEMETRY STREAM</span>
          <span className="text-[10px] text-cyan-300 bg-cyan-950 px-2 py-0.5 rounded border border-cyan-800/40 hidden sm:inline font-bold">
            {logs.length} EVENTS BUFFERED
          </span>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={togglePause}
            className={`p-1.5 rounded-lg border text-[11px] font-mono flex items-center gap-1 transition ${
              isPaused 
                ? 'bg-amber-950/80 text-amber-300 border-amber-700/60 hover:bg-amber-900' 
                : 'bg-cyan-950/80 text-cyan-300 border-cyan-800/60 hover:bg-cyan-900'
            }`}
            title={isPaused ? "Resume Stream" : "Pause Stream"}
          >
            {isPaused ? <Play className="w-3 h-3" /> : <Pause className="w-3 h-3" />}
            <span className="hidden md:inline">{isPaused ? 'RESUME' : 'PAUSE'}</span>
          </button>

          <button
            onClick={clearLogs}
            className="p-1.5 rounded-lg border border-white/[0.08] bg-slate-950/80 hover:bg-slate-900 text-slate-400 hover:text-white transition"
            title="Clear Buffer"
          >
            <Trash2 className="w-3 h-3" />
          </button>

          <button className="p-1.5 text-slate-400 hover:text-white">
            {isOpen ? <ChevronDown className="w-4 h-4" /> : <ChevronUp className="w-4 h-4" />}
          </button>
        </div>
      </div>

      {/* Expanded Terminal View */}
      {isOpen && (
        <div className="p-4 bg-[#040813]/95 border-t border-cyan-900/30">
          <div 
            ref={scrollRef}
            className="h-56 overflow-y-auto font-mono text-[11px] space-y-1.5 pr-2 custom-scrollbar"
          >
            {logs.length > 0 ? (
              logs.map(log => (
                <div 
                  key={log.id} 
                  className="flex items-start gap-2.5 py-0.5 hover:bg-white/[0.02] px-1.5 rounded transition"
                >
                  <span className="text-slate-500 shrink-0 select-none">[{log.time}]</span>
                  <span className={`px-1.5 py-0.2 rounded text-[9px] font-bold shrink-0 ${
                    log.source === 'KERNEL' ? 'bg-indigo-950 text-indigo-300 border border-indigo-800/40' :
                    log.source === 'MEMORY' ? 'bg-rose-950 text-rose-300 border border-rose-800/40' :
                    log.source === 'NETWORK' ? 'bg-cyan-950 text-cyan-300 border border-cyan-800/40' :
                    log.source === 'YARA' ? 'bg-purple-950 text-purple-300 border border-purple-800/40' :
                    'bg-slate-800 text-slate-300'
                  }`}>
                    {log.source}
                  </span>
                  <span className={`flex-1 break-all ${
                    log.level === 'CRIT' ? 'text-rose-300 font-semibold' :
                    log.level === 'WARN' ? 'text-amber-300' :
                    'text-slate-300'
                  }`}>
                    {log.message}
                  </span>
                </div>
              ))
            ) : (
              <div className="text-center py-10 text-slate-500 italic">
                Telemetry buffer cleared. Listening for dynamic syscall hooks...
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
