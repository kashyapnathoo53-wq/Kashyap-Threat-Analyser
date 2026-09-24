import React, { useState } from 'react';
import { ProcessNode } from '../types';
import { Terminal, ChevronRight, ChevronDown, Cpu, AlertTriangle } from 'lucide-react';

interface ProcessTreeProps {
  node: ProcessNode;
  depth?: number;
}

export const ProcessTreeGraph: React.FC<ProcessTreeProps> = ({ node, depth = 0 }) => {
  const [expanded, setExpanded] = useState(true);
  const hasChildren = node.children && node.children.length > 0;

  const isMaliciousProc = node.name.toLowerCase().includes("cmd") ||
                          node.name.toLowerCase().includes("vssadmin") ||
                          node.name.toLowerCase().includes("powershell") ||
                          node.name.toLowerCase().includes("sample") ||
                          node.name.toLowerCase().includes("steal");

  return (
    <div className="ml-4 border-l border-slate-700/60 pl-3 my-2">
      <div 
        className={`flex items-center gap-2 p-2.5 rounded-lg border transition-all ${
          isMaliciousProc 
            ? 'bg-rose-950/30 border-rose-500/40 text-rose-200' 
            : 'bg-slate-900/60 border-cyan-900/30 text-slate-200 hover:border-cyan-500/50'
        }`}
      >
        {hasChildren ? (
          <button 
            onClick={() => setExpanded(!expanded)} 
            className="p-1 text-slate-400 hover:text-white rounded"
          >
            {expanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
          </button>
        ) : (
          <div className="w-4" />
        )}

        {isMaliciousProc ? (
          <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
        ) : (
          <Cpu className="w-4 h-4 text-cyan-400 shrink-0" />
        )}

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className={`font-mono font-bold text-sm ${isMaliciousProc ? 'text-rose-300' : 'text-cyan-300'}`}>{node.name}</span>
            <span className="px-1.5 py-0.5 text-xs font-mono bg-slate-800 text-slate-400 rounded">PID: {node.pid}</span>
            <span className={`px-1.5 py-0.5 text-xs font-mono rounded ${node.integrity === 'SYSTEM' || node.integrity === 'High' ? 'bg-amber-900/50 text-amber-300' : 'bg-slate-800 text-slate-400'}`}>
              Integrity: {node.integrity}
            </span>
          </div>
          <div className="text-xs font-mono text-slate-400 truncate mt-0.5" title={node.cmd}>
            {node.cmd}
          </div>
        </div>
      </div>

      {hasChildren && expanded && (
        <div className="mt-1">
          {node.children!.map((child) => (
            <ProcessTreeGraph key={child.pid} node={child} depth={depth + 1} />
          ))}
        </div>
      )}
    </div>
  );
};
