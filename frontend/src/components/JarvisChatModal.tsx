import React, { useState, useEffect, useRef } from 'react';
import { FullAnalysisReport, HostAssessment } from '../types';
import { jarvisVoice } from '../utils/jarvisVoice';
import { cyberAudio } from '../utils/cyberAudio';
import { 
  Bot, Send, Mic, MicOff, Volume2, VolumeX, X, Sparkles, 
  Terminal, ShieldAlert, Check, Copy, User, RefreshCw, MessageSquare
} from 'lucide-react';

interface ChatMessage {
  id: string;
  sender: 'user' | 'jarvis';
  text: string;
  timestamp: string;
}

interface JarvisChatModalProps {
  report: FullAnalysisReport | null;
  hostAssessment: HostAssessment | null;
  isOpen: boolean;
  onClose: () => void;
  initialPrompt?: string;
}

export const JarvisChatModal: React.FC<JarvisChatModalProps> = ({
  report,
  hostAssessment,
  isOpen,
  onClose,
  initialPrompt
}) => {
  const [messages, setMessages] = useState<ChatMessage[]>(() => [
    {
      id: 'welcome',
      sender: 'jarvis',
      text: "At your service, sir. I have fully indexed the forensic telemetry for the active payload and local host environment. You may ask me any questions regarding malware eradication, suspicious PIDs, registry scrubbing, or threat neutralization protocols.",
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    }
  ]);
  const [inputText, setInputText] = useState<string>('');
  const [isTyping, setIsTyping] = useState<boolean>(false);
  const [isListening, setIsListening] = useState<boolean>(false);
  const [autoSpeak, setAutoSpeak] = useState<boolean>(true);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const messagesEndRef = useRef<HTMLDivElement | null>(null);
  const recognitionRef = useRef<any>(null);

  // Auto-scroll to bottom of chat
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, isTyping]);

  // Handle initial prompt if passed
  useEffect(() => {
    if (initialPrompt && isOpen) {
      handleSendMessage(initialPrompt);
    }
  }, [initialPrompt, isOpen]);

  // Setup Web Speech Recognition for voice input if supported
  useEffect(() => {
    if (typeof window !== 'undefined') {
      const SpeechRecognitionClass = (window as any).SpeechRecognition || (window as any).webkitSpeechRecognition;
      if (SpeechRecognitionClass) {
        const recognition = new SpeechRecognitionClass();
        recognition.continuous = false;
        recognition.interimResults = false;
        recognition.lang = 'en-US';

        recognition.onresult = (event: any) => {
          const transcript = event.results[0][0].transcript;
          setInputText(transcript);
          setIsListening(false);
          handleSendMessage(transcript);
        };

        recognition.onerror = () => {
          setIsListening(false);
        };

        recognition.onend = () => {
          setIsListening(false);
        };

        recognitionRef.current = recognition;
      }
    }
  }, []);

  const toggleVoiceInput = () => {
    cyberAudio.playClick();
    if (!recognitionRef.current) {
      alert("Speech recognition is not supported in this browser. Please type your question.");
      return;
    }

    if (isListening) {
      recognitionRef.current.stop();
      setIsListening(false);
    } else {
      try {
        recognitionRef.current.start();
        setIsListening(true);
      } catch {
        setIsListening(false);
      }
    }
  };

  const handleSendMessage = async (textToSend?: string) => {
    const query = (textToSend || inputText).trim();
    if (!query || isTyping) return;

    cyberAudio.playClick();
    const userMsg: ChatMessage = {
      id: Date.now().toString(),
      sender: 'user',
      text: query,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    };

    setMessages(prev => [...prev, userMsg]);
    setInputText('');
    setIsTyping(true);

    try {
      // Call backend API
      const res = await fetch('/api/jarvis/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: query,
          report,
          host_assessment: hostAssessment,
          history: messages.slice(-4).map(m => ({ role: m.sender, content: m.text }))
        })
      });

      let replyText = '';
      if (res.ok) {
        const data = await res.json();
        replyText = data.reply;
      } else {
        throw new Error('API failed');
      }

      const jarvisMsg: ChatMessage = {
        id: (Date.now() + 1).toString(),
        sender: 'jarvis',
        text: replyText,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      };

      setMessages(prev => [...prev, jarvisMsg]);

      // Automatically vocalize J.A.R.V.I.S. response if autoSpeak is on
      if (autoSpeak) {
        // Strip code blocks and markdown for clean speech
        const speechClean = replyText.replace(/```[\s\S]*?```/g, 'Refer to the administrative terminal code block below, sir.').replace(/[#*`_]/g, '');
        jarvisVoice.speak(speechClean, 'solution');
      }
    } catch {
      // Intelligent client-side fallback
      const sample = report?.sample_name || 'suspicious payload';
      const fallbackReply = `Sir, regarding your inquiry: To remediate ${sample}, I advise isolating network adapters via 'Disable-NetAdapter', terminating suspicious processes with 'Stop-Process -Force', and inspecting the interactive Flowchart Roadmap in your System Assessment dashboard.`;
      
      const jarvisMsg: ChatMessage = {
        id: (Date.now() + 1).toString(),
        sender: 'jarvis',
        text: fallbackReply,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      };
      setMessages(prev => [...prev, jarvisMsg]);
      if (autoSpeak) {
        jarvisVoice.speak(fallbackReply, 'solution');
      }
    } finally {
      setIsTyping(false);
    }
  };

  const speakMessage = (text: string) => {
    cyberAudio.playClick();
    const speechClean = text.replace(/```[\s\S]*?```/g, 'Refer to the administrative command block, sir.').replace(/[#*`_]/g, '');
    jarvisVoice.speak(speechClean, 'solution');
  };

  const copyText = (id: string, text: string) => {
    cyberAudio.playClick();
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  if (!isOpen) return null;

  const quickPrompts = [
    "How do I completely eradicate this malware from my host?",
    "Which process PIDs should I terminate immediately?",
    "Give me the PowerShell commands to clean the registry.",
    "Explain why this file is classified as dangerous.",
    "Is my local network compromised by this payload?"
  ];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-4 bg-black/85 backdrop-blur-md animate-fadeIn">
      <div 
        className="relative w-full max-w-3xl h-[88vh] flex flex-col rounded-3xl overflow-hidden border border-amber-500/40 shadow-2xl bg-[#0c0305]"
        style={{
          backgroundImage: 'radial-gradient(ellipse at 50% 0%, rgba(220, 38, 38, 0.18) 0%, rgba(12, 3, 5, 0.98) 75%)'
        }}
      >
        {/* Top Header Bar */}
        <div className="px-5 py-4 border-b border-amber-900/40 flex items-center justify-between bg-[#150508]/90">
          <div className="flex items-center gap-3">
            <div className="relative">
              <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-red-600 via-amber-600 to-yellow-500 flex items-center justify-center text-slate-950 font-black shadow-lg shadow-red-950/80">
                <Bot className="w-5 h-5 stroke-[2.5]" />
              </div>
              <span className="absolute -bottom-1 -right-1 flex h-3 w-3">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75" />
                <span className="relative inline-flex rounded-full h-3 w-3 bg-cyan-400" />
              </span>
            </div>

            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-sm sm:text-base font-black text-white tracking-wide">
                  TALK TO J.A.R.V.I.S. ASSISTANT
                </h3>
                <span className="px-2 py-0.5 text-[9px] font-mono font-black uppercase rounded-full bg-amber-950 text-amber-300 border border-amber-500/40">
                  AI Q&amp;A READY
                </span>
              </div>
              <p className="text-xs text-slate-400 font-mono">
                Ask questions about malware eradication, system health, or specific indicators
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {/* Auto-Speak Toggle */}
            <button
              onClick={() => {
                cyberAudio.playClick();
                setAutoSpeak(!autoSpeak);
              }}
              className={`flex items-center gap-1 px-2.5 py-1.5 rounded-xl border text-[11px] font-mono font-bold transition cursor-pointer ${
                autoSpeak 
                  ? 'bg-amber-950 text-amber-300 border-amber-500/50' 
                  : 'bg-slate-900 text-slate-500 border-white/10'
              }`}
              title={autoSpeak ? "Voice responses active (Click to mute)" : "Voice responses muted"}
            >
              {autoSpeak ? <Volume2 className="w-3.5 h-3.5 text-amber-400 animate-pulse" /> : <VolumeX className="w-3.5 h-3.5" />}
              <span className="hidden sm:inline">{autoSpeak ? 'Voice: On' : 'Voice: Off'}</span>
            </button>

            {/* Close Button */}
            <button
              onClick={() => {
                cyberAudio.playClick();
                jarvisVoice.stop();
                onClose();
              }}
              className="p-2 rounded-xl text-slate-400 hover:text-white bg-slate-900/80 border border-white/10 hover:border-amber-400 transition cursor-pointer"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Message Stream */}
        <div className="flex-1 overflow-y-auto p-4 sm:p-5 space-y-4 select-text">
          {messages.map((msg) => {
            const isJarvis = msg.sender === 'jarvis';
            return (
              <div 
                key={msg.id} 
                className={`flex items-start gap-3 ${isJarvis ? 'justify-start' : 'justify-end'}`}
              >
                {isJarvis && (
                  <div className="w-8 h-8 rounded-xl bg-gradient-to-tr from-red-600 to-amber-500 flex items-center justify-center text-slate-950 shrink-0 font-black shadow-md mt-1">
                    <Bot className="w-4 h-4" />
                  </div>
                )}

                <div 
                  className={`max-w-[85%] sm:max-w-[75%] rounded-2xl p-4 text-xs leading-relaxed ${
                    isJarvis 
                      ? 'bg-[#18060a] border border-amber-900/50 text-slate-200 shadow-lg' 
                      : 'bg-gradient-to-r from-red-700/80 via-amber-600/80 to-yellow-600/80 text-white font-medium border border-amber-400/40 shadow-md ml-auto'
                  }`}
                >
                  <div className="flex items-center justify-between text-[10px] font-mono text-slate-400 mb-1 pb-1 border-b border-white/[0.06]">
                    <span className="font-bold text-amber-300">
                      {isJarvis ? 'J.A.R.V.I.S. ADVISOR' : 'SECURITY ANALYST'}
                    </span>
                    <span>{msg.timestamp}</span>
                  </div>

                  <div className="whitespace-pre-wrap space-y-2">
                    {msg.text.split('\n\n').map((para, i) => {
                      if (para.startsWith('```')) {
                        const code = para.replace(/```(powershell|bash)?/g, '').trim();
                        return (
                          <div key={i} className="my-2 p-3 bg-black/80 rounded-xl border border-white/10 font-mono text-amber-200 overflow-x-auto relative group">
                            <pre className="text-[11px]">{code}</pre>
                            <button
                              onClick={() => copyText(`${msg.id}_code`, code)}
                              className="absolute top-2 right-2 px-2 py-0.5 rounded bg-slate-900 text-slate-300 border border-white/10 text-[9px] hover:text-white transition"
                            >
                              {copiedId === `${msg.id}_code` ? 'Copied' : 'Copy'}
                            </button>
                          </div>
                        );
                      }
                      return <p key={i}>{para}</p>;
                    })}
                  </div>

                  {isJarvis && (
                    <div className="mt-2.5 pt-2 border-t border-white/[0.05] flex items-center justify-between text-[10px] font-mono text-slate-400">
                      <button
                        onClick={() => speakMessage(msg.text)}
                        className="flex items-center gap-1 hover:text-amber-300 transition cursor-pointer"
                        title="Vocalize this answer"
                      >
                        <Volume2 className="w-3.5 h-3.5 text-cyan-400" />
                        <span>Listen Aloud</span>
                      </button>

                      <button
                        onClick={() => copyText(msg.id, msg.text)}
                        className="flex items-center gap-1 hover:text-white transition cursor-pointer"
                      >
                        {copiedId === msg.id ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3 text-amber-400" />}
                        <span>{copiedId === msg.id ? 'Copied' : 'Copy Text'}</span>
                      </button>
                    </div>
                  )}
                </div>

                {!isJarvis && (
                  <div className="w-8 h-8 rounded-xl bg-slate-800 flex items-center justify-center text-slate-300 shrink-0 font-bold border border-white/10 mt-1">
                    <User className="w-4 h-4" />
                  </div>
                )}
              </div>
            );
          })}

          {isTyping && (
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-xl bg-gradient-to-tr from-red-600 to-amber-500 flex items-center justify-center text-slate-950 shrink-0 font-black shadow-md">
                <Bot className="w-4 h-4 animate-spin" />
              </div>
              <div className="bg-[#18060a] border border-amber-900/50 rounded-2xl p-3 text-xs text-amber-300 flex items-center gap-2">
                <span className="w-1.5 h-1.5 bg-amber-400 rounded-full animate-bounce" style={{ animationDelay: '0ms' }} />
                <span className="w-1.5 h-1.5 bg-cyan-400 rounded-full animate-bounce" style={{ animationDelay: '150ms' }} />
                <span className="w-1.5 h-1.5 bg-red-400 rounded-full animate-bounce" style={{ animationDelay: '300ms' }} />
                <span>J.A.R.V.I.S. Synthesizing Answer...</span>
              </div>
            </div>
          )}

          <div ref={messagesEndRef} />
        </div>

        {/* Quick Suggestion Pills */}
        <div className="px-4 py-2 border-t border-amber-900/30 bg-[#0f0305] flex items-center gap-1.5 overflow-x-auto text-[11px] font-sans scrollbar-none">
          <span className="text-slate-400 font-mono text-[10px] shrink-0 font-bold">Suggestions:</span>
          {quickPrompts.map((p, idx) => (
            <button
              key={idx}
              type="button"
              onClick={() => handleSendMessage(p)}
              className="px-2.5 py-1 rounded-lg bg-slate-900/90 hover:bg-amber-950 text-slate-300 hover:text-amber-200 border border-white/[0.08] hover:border-amber-500/40 whitespace-nowrap transition cursor-pointer"
            >
              {p}
            </button>
          ))}
        </div>

        {/* Chat Input Bar */}
        <div className="p-3 sm:p-4 border-t border-amber-900/40 bg-[#140507]">
          <form 
            onSubmit={(e) => {
              e.preventDefault();
              handleSendMessage();
            }}
            className="flex items-center gap-2"
          >
            {/* Voice Input Button */}
            <button
              type="button"
              onClick={toggleVoiceInput}
              className={`p-2.5 rounded-xl border transition cursor-pointer ${
                isListening 
                  ? 'bg-red-600 text-white border-red-400 animate-pulse' 
                  : 'bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-white border-white/10'
              }`}
              title={isListening ? "Listening... Click to stop" : "Speak question using microphone"}
            >
              {isListening ? <MicOff className="w-4 h-4" /> : <Mic className="w-4 h-4" />}
            </button>

            <input
              type="text"
              value={inputText}
              onChange={(e) => setInputText(e.target.value)}
              placeholder="Ask J.A.R.V.I.S. about malware removal, process PIDs, registry, or mitigation..."
              className="flex-1 bg-slate-950 border border-amber-900/50 focus:border-amber-400 rounded-xl px-4 py-2.5 text-xs text-white placeholder-slate-500 focus:outline-none transition shadow-inner font-sans"
            />

            <button
              type="submit"
              disabled={!inputText.trim() || isTyping}
              className="px-4 py-2.5 bg-gradient-to-r from-red-600 via-amber-600 to-yellow-500 hover:from-red-500 hover:to-yellow-400 text-slate-950 font-black text-xs rounded-xl transition shadow-lg shadow-red-950/80 active:scale-95 disabled:opacity-50 cursor-pointer flex items-center gap-1.5"
            >
              <span>Send</span>
              <Send className="w-3.5 h-3.5" />
            </button>
          </form>
        </div>
      </div>
    </div>
  );
};
