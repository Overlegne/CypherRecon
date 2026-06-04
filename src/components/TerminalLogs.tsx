"use client";

import { useEffect, useRef } from 'react';
import { LogEntry } from '@/lib/types';
import { ScrollArea } from './ui/scroll-area';
import { format } from 'date-fns';

export function TerminalLogs({ logs }: { logs: LogEntry[] }) {
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [logs]);

  return (
    <div className="bg-black/40 rounded-lg border border-border p-4 h-[300px] flex flex-col">
      <div className="flex items-center gap-2 mb-2 border-b border-white/5 pb-2">
        <div className="flex gap-1.5">
          <div className="w-3 h-3 rounded-full bg-red-500/20 border border-red-500/40" />
          <div className="w-3 h-3 rounded-full bg-yellow-500/20 border border-yellow-500/40" />
          <div className="w-3 h-3 rounded-full bg-green-500/20 border border-green-500/40" />
        </div>
        <span className="text-xs text-muted-foreground font-code ml-2 uppercase tracking-widest">Recon Console</span>
      </div>
      <ScrollArea className="flex-1 pr-4">
        <div className="space-y-1">
          {logs.length === 0 && (
            <p className="text-muted-foreground font-code text-xs italic">Awaiting sequence initiation...</p>
          )}
          {logs.map((log) => (
            <div key={log.id} className="font-code text-xs flex gap-3 leading-relaxed">
              <span className="text-muted-foreground shrink-0 select-none">
                [{format(log.timestamp, 'HH:mm:ss')}]
              </span>
              <span className={
                log.type === 'error' ? 'text-destructive' :
                log.type === 'warn' ? 'text-yellow-400' :
                log.type === 'success' ? 'text-green-400' :
                'text-primary'
              }>
                {log.message}
              </span>
            </div>
          ))}
          <div ref={scrollRef} />
        </div>
      </ScrollArea>
    </div>
  );
}