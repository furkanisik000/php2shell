"use client";

import { useEffect, useRef, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { Play, Pause, RotateCcw, Check, ChevronDown, ShieldCheck } from "lucide-react";
import { REAL_WORLD_STAGES } from "@/lib/real-world-kill-chain";
import { TerminalPanel } from "@/components/TerminalPanel";
import { ExploitFlowDiagram } from "@/components/ExploitFlowDiagram";
import { RequestExploitAnimation } from "@/components/RequestExploitAnimation";
import { CodeComparison } from "@/components/CodeComparison";
import { cn } from "@/lib/utils";

const AUTOPLAY_MS = 4200;

export function RealWorldKillChain() {
  const [activeIndex, setActiveIndex] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [visited, setVisited] = useState<Set<number>>(() => new Set([0]));
  const [runId, setRunId] = useState(0);
  const [openTechnique, setOpenTechnique] = useState<string | null>(null);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const stage = REAL_WORLD_STAGES[activeIndex];
  const lastIndex = REAL_WORLD_STAGES.length - 1;

  function goTo(i: number) {
    const clamped = Math.max(0, Math.min(lastIndex, i));
    setActiveIndex(clamped);
    setVisited((prev) => new Set(prev).add(clamped));
    setOpenTechnique(null);
  }

  useEffect(() => {
    if (!playing) return;
    intervalRef.current = setInterval(() => {
      setActiveIndex((prev) => {
        const next = prev + 1;
        if (next > lastIndex) {
          setPlaying(false);
          return prev;
        }
        setVisited((v) => new Set(v).add(next));
        return next;
      });
    }, AUTOPLAY_MS);
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, [playing, lastIndex]);

  function togglePlay() {
    setPlaying((p) => {
      const next = !p;
      if (next) setRunId((r) => r + 1);
      return next;
    });
  }

  function restart() {
    setPlaying(false);
    setActiveIndex(0);
    setVisited(new Set([0]));
  }

  const progressPct = (activeIndex / lastIndex) * 100;

  return (
    <div className="w-full select-none">
      <div className="flex flex-wrap items-center justify-between gap-3 mb-5">
        <div className="flex items-center gap-2">
          <button
            onClick={togglePlay}
            className="inline-flex items-center gap-1.5 rounded-full bg-php hover:bg-php-light text-white text-sm font-medium px-4 py-2 transition-colors"
            aria-label={playing ? "Pause timeline" : "Play incident timeline"}
          >
            {playing ? <Pause className="h-3.5 w-3.5" /> : <Play className="h-3.5 w-3.5" />}
            {playing ? "Pause" : "Play the timeline"}
          </button>
          <button
            onClick={restart}
            className="inline-flex items-center gap-1.5 rounded-full border border-border hover:bg-accent text-sm px-3 py-2 transition-colors"
            aria-label="Restart"
          >
            <RotateCcw className="h-3.5 w-3.5" /> Restart
          </button>
        </div>
        <span className="label-console">
          {activeIndex + 1} / {REAL_WORLD_STAGES.length}
        </span>
      </div>

      <div className="relative mb-8">
        <div className="absolute left-0 right-0 top-5 h-0.5 bg-border" />
        <motion.div
          className="absolute left-0 top-5 h-0.5 bg-php"
          animate={{ width: `${progressPct}%` }}
          transition={{ duration: 0.5, ease: "easeInOut" }}
        />
        <div className="relative flex justify-between">
          {REAL_WORLD_STAGES.map((s, i) => {
            const isActive = i === activeIndex;
            const isVisited = visited.has(i);
            return (
              <button
                key={s.id}
                onClick={() => {
                  setPlaying(false);
                  goTo(i);
                }}
                className="flex flex-col items-center gap-1.5"
                style={{ width: `${100 / REAL_WORLD_STAGES.length}%` }}
                aria-current={isActive}
              >
                <span
                  className={cn(
                    "flex h-10 w-10 items-center justify-center rounded-full border-2 font-heading font-semibold text-xs transition-all",
                    isActive
                      ? "scale-110 border-transparent text-white shadow-lg"
                      : isVisited
                        ? "border-transparent text-white/90"
                        : "border-border bg-card text-muted-foreground"
                  )}
                  style={
                    isActive || isVisited
                      ? { background: `linear-gradient(135deg, ${s.colorFrom}, ${s.colorTo})` }
                      : undefined
                  }
                >
                  {isVisited && !isActive ? <Check className="h-4 w-4" /> : s.order}
                </span>
                <span className={cn("text-[11px] text-center leading-tight", isActive ? "text-foreground font-medium" : "text-muted-foreground")}>
                  {s.shortLabel}
                </span>
              </button>
            );
          })}
        </div>
      </div>

      <ExploitFlowDiagram active={playing} accentColor={stage.colorFrom} label={stage.title} runKey={`${activeIndex}-${runId}`} />

      <AnimatePresence mode="wait">
        <motion.div
          key={stage.id}
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -8 }}
          transition={{ duration: 0.25 }}
        >
          <TerminalPanel lines={stage.logLines} live={playing} accentColor={stage.colorFrom} runKey={runId} />
          <p className="mt-3 mb-4 text-sm text-muted-foreground leading-relaxed">{stage.detail}</p>

          {stage.stats && (
            <div className="grid grid-cols-2 gap-2 mb-4 sm:grid-cols-4">
              {stage.stats.map((s) => (
                <div key={s.label} className="border border-border p-3 text-center">
                  <div className="font-heading text-lg font-bold text-vulnerable">{s.value}</div>
                  <div className="mt-0.5 text-[11px] leading-tight text-muted-foreground">{s.label}</div>
                </div>
              ))}
            </div>
          )}

          {stage.example && (
            <div className="mb-4">
              <h4 className="label-console mb-2">What it looks like</h4>
              <CodeComparison
                vulnerableCode={stage.example.vulnerable}
                secureCode={stage.example.secure}
                language={stage.example.language ?? "dockerfile"}
              />
            </div>
          )}

          {stage.techniques && (
            <div className="grid gap-2 sm:grid-cols-2 mb-4">
              {stage.techniques.map((t) => {
                const open = openTechnique === t.id;
                return (
                  <div
                    key={t.id}
                    className={cn("rounded-lg border overflow-hidden transition-colors", open ? "border-php" : "border-border")}
                  >
                    <button
                      onClick={() => setOpenTechnique(open ? null : t.id)}
                      className="w-full flex items-center justify-between gap-2 px-3.5 py-2.5 text-left hover:bg-accent/50 transition-colors"
                      aria-expanded={open}
                    >
                      <span className="text-sm font-medium">{t.name}</span>
                      <ChevronDown className={cn("h-4 w-4 text-muted-foreground shrink-0 transition-transform", open && "rotate-180")} />
                    </button>
                    <AnimatePresence initial={false}>
                      {open && (
                        <motion.div
                          initial={{ height: 0, opacity: 0 }}
                          animate={{ height: "auto", opacity: 1 }}
                          exit={{ height: 0, opacity: 0 }}
                          transition={{ duration: 0.2 }}
                          className="px-3.5 pb-3.5 space-y-2"
                        >
                          <p className="text-xs text-muted-foreground leading-relaxed">{t.detail}</p>
                          {t.requests && (
                            <RequestExploitAnimation
                              requests={t.requests}
                              finalResult={t.finalResult}
                              accentColor={stage.colorFrom}
                            />
                          )}
                          <div className="flex items-start gap-1.5 text-xs text-safe">
                            <ShieldCheck className="h-3.5 w-3.5 shrink-0 mt-0.5" />
                            <span className="leading-relaxed">{t.defense}</span>
                          </div>
                        </motion.div>
                      )}
                    </AnimatePresence>
                  </div>
                );
              })}
            </div>
          )}
        </motion.div>
      </AnimatePresence>
    </div>
  );
}
