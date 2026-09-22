import React, { useEffect, useRef } from 'react';

interface Particle {
  x: number;
  y: number;
  vx: number;
  vy: number;
  radius: number;
  alpha: number;
  color: string;
}

interface Props {
  theme?: 'ironman' | 'cyan' | 'emerald' | 'violet' | 'amber';
}

const THEME_PALETTES = {
  ironman: {
    particles: ['#fbbf24', '#f59e0b', '#dc2626', '#ef4444', '#00f2fe', '#fde047'],
    filament: '#fbbf24'
  },
  cyan: {
    particles: ['#00f2fe', '#06b6d4', '#38bdf8', '#22d3ee', '#67e8f9'],
    filament: '#06b6d4'
  },
  emerald: {
    particles: ['#10b981', '#059669', '#34d399', '#6ee7b7', '#00ff9d'],
    filament: '#10b981'
  },
  violet: {
    particles: ['#a855f7', '#8b5cf6', '#c084fc', '#d8b4fe', '#7c3aed'],
    filament: '#a855f7'
  },
  amber: {
    particles: ['#f97316', '#ea580c', '#fb923c', '#fdba74', '#f59e0b'],
    filament: '#f97316'
  }
};

export const CyberParticleCanvas: React.FC<Props> = ({ theme = 'ironman' }) => {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animationFrameId: number;
    let width = (canvas.width = window.innerWidth);
    let height = (canvas.height = window.innerHeight);

    const handleResize = () => {
      if (!canvas) return;
      width = canvas.width = window.innerWidth;
      height = canvas.height = window.innerHeight;
    };
    window.addEventListener('resize', handleResize);

    const mouse = { x: -1000, y: -1000, radius: 140 };

    const handleMouseMove = (e: MouseEvent) => {
      mouse.x = e.clientX;
      mouse.y = e.clientY;
    };

    const handleMouseLeave = () => {
      mouse.x = -1000;
      mouse.y = -1000;
    };

    window.addEventListener('mousemove', handleMouseMove);
    window.addEventListener('mouseleave', handleMouseLeave);

    const currentPalette = THEME_PALETTES[theme] || THEME_PALETTES.cyan;
    const particleCount = Math.min(55, Math.floor((width * height) / 24000));
    const particles: Particle[] = [];
    const colors = currentPalette.particles;

    for (let i = 0; i < particleCount; i++) {
      particles.push({
        x: Math.random() * width,
        y: Math.random() * height,
        vx: (Math.random() - 0.5) * 0.7,
        vy: (Math.random() - 0.5) * 0.7,
        radius: Math.random() * 2 + 1,
        alpha: Math.random() * 0.6 + 0.25,
        color: colors[Math.floor(Math.random() * colors.length)]
      });
    }

    const maxDistance = 120;

    const render = () => {
      ctx.clearRect(0, 0, width, height);

      for (let i = 0; i < particles.length; i++) {
        const p1 = particles[i];
        p1.x += p1.vx;
        p1.y += p1.vy;

        if (p1.x < 0 || p1.x > width) p1.vx *= -1;
        if (p1.y < 0 || p1.y > height) p1.vy *= -1;

        const dx = p1.x - mouse.x;
        const dy = p1.y - mouse.y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < mouse.radius) {
          const force = (mouse.radius - dist) / mouse.radius;
          const angle = Math.atan2(dy, dx);
          p1.x += Math.cos(angle) * force * 2.2;
          p1.y += Math.sin(angle) * force * 2.2;
        }

        ctx.beginPath();
        ctx.arc(p1.x, p1.y, p1.radius, 0, Math.PI * 2);
        ctx.fillStyle = p1.color;
        ctx.globalAlpha = p1.alpha;
        ctx.shadowBlur = 8;
        ctx.shadowColor = p1.color;
        ctx.fill();

        for (let j = i + 1; j < particles.length; j++) {
          const p2 = particles[j];
          const distBetween = Math.hypot(p1.x - p2.x, p1.y - p2.y);

          if (distBetween < maxDistance) {
            const lineAlpha = (1 - distBetween / maxDistance) * 0.22;
            ctx.beginPath();
            ctx.moveTo(p1.x, p1.y);
            ctx.lineTo(p2.x, p2.y);
            ctx.strokeStyle = currentPalette.filament;
            ctx.globalAlpha = lineAlpha;
            ctx.lineWidth = 0.8;
            ctx.stroke();
          }
        }
      }

      ctx.globalAlpha = 1;
      ctx.shadowBlur = 0;
      animationFrameId = requestAnimationFrame(render);
    };

    render();

    return () => {
      window.removeEventListener('resize', handleResize);
      window.removeEventListener('mousemove', handleMouseMove);
      window.removeEventListener('mouseleave', handleMouseLeave);
      cancelAnimationFrame(animationFrameId);
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      className="pointer-events-none fixed inset-0 z-0 opacity-40"
    />
  );
};
