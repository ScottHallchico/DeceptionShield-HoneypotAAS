import { useEffect, useRef, useState } from "react";
import { Link } from "@tanstack/react-router";
import { Bot, Loader2, Send, Sparkles, X } from "lucide-react";
import { useAssistantQuery } from "@/api/queries";
import { useUiStore } from "@/store/ui";
import type { AssistantMessage } from "@/types/api";
import { cn } from "@/lib/utils";
import ReactMarkdown from "react-markdown";

const SUGGESTIONS = [
  "What's hit the RDP decoy in the last hour?",
  "Summarize critical events today",
  "Who's brute-forcing cowrie-ssh-01?",
];

export function ThreatAssistant() {
  const [open, setOpen] = useState(false);
  const [input, setInput] = useState("");
  const [messages, setMessages] = useState<AssistantMessage[]>([]);
  const [conversationId, setConversationId] = useState<string | undefined>();
  const selectAttacker = useUiStore((s) => s.selectAttacker);
  const scrollRef = useRef<HTMLDivElement>(null);
  const { mutate, isPending } = useAssistantQuery();

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: "smooth" });
  }, [messages, isPending]);

  const ask = (question: string) => {
    if (!question.trim() || isPending) return;
    const userMsg: AssistantMessage = {
      id: crypto.randomUUID(),
      role: "user",
      content: question.trim(),
      created_at: new Date().toISOString(),
    };
    setMessages((m) => [...m, userMsg]);
    setInput("");

    mutate(
      conversationId ? { question: question.trim(), conversationId } : { question: question.trim() },
      {
        onSuccess: (res) => {
          setConversationId(res.conversation_id);
          setMessages((m) => [...m, res.message]);
        },
        onError: () => {
          setMessages((m) => [
            ...m,
            {
              id: crypto.randomUUID(),
              role: "assistant",
              content: "Couldn't reach the assistant service — try again in a moment.",
              created_at: new Date().toISOString(),
            },
          ]);
        },
      },
    );
  };

  return (
    <>
      {open ? (
        <div
          role="dialog"
          aria-label="Threat assistant"
          className="panel fixed right-3 bottom-3 z-40 flex h-[min(560px,calc(100vh-2rem))] w-[min(380px,calc(100vw-1.5rem))] flex-col sm:right-5 sm:bottom-5"
        >
          <header className="flex items-center justify-between border-b border-border px-3.5 py-2.5">
            <div className="flex items-center gap-2">
              <Sparkles className="h-3.5 w-3.5 text-primary" strokeWidth={2.5} />
              <span className="label-caps !text-foreground">Threat Assistant</span>
            </div>
            <button
              type="button"
              aria-label="Close assistant"
              onClick={() => setOpen(false)}
              className="text-muted-foreground hover:text-foreground"
            >
              <X className="h-4 w-4" />
            </button>
          </header>

          <div ref={scrollRef} className="min-h-0 flex-1 space-y-3 overflow-y-auto px-3.5 py-3">
            {messages.length === 0 ? (
              <div className="space-y-2">
                <p className="text-xs leading-relaxed text-muted-foreground">
                  Ask about live or historical activity across your decoy fleet — grounded in
                  actual captured events, with citations you can open.
                </p>
                <div className="flex flex-col gap-1.5">
                  {SUGGESTIONS.map((s) => (
                    <button
                      key={s}
                      type="button"
                      onClick={() => ask(s)}
                      className="border border-border bg-surface-raised px-2.5 py-1.5 text-left text-xs text-muted-foreground hover:border-border-strong hover:text-foreground"
                    >
                      {s}
                    </button>
                  ))}
                </div>
              </div>
            ) : null}

            {messages.map((m) => (
              <div
                key={m.id}
                className={cn("flex", m.role === "user" ? "justify-end" : "justify-start")}
              >
                <div
                  className={cn(
                    "max-w-[88%] px-2.5 py-2 text-xs leading-relaxed",
                    m.role === "user"
                      ? "bg-primary/10 text-foreground"
                      : "border border-border bg-surface-raised text-foreground",
                  )}
                >
                  <div className="prose prose-sm prose-invert max-w-none text-xs leading-relaxed dark:prose-invert [&>p]:mb-2 last:[&>p]:mb-0 [&>ul]:pl-4 [&>ul]:list-disc [&>ul]:mb-2 [&>li]:mb-1">
                    <ReactMarkdown>{m.content}</ReactMarkdown>
                  </div>
                  {m.citations?.length ? (
                    <div className="mt-2 flex flex-wrap gap-1.5 border-t border-border pt-2">
                      {m.citations.map((c) =>
                        c.session_id ? (
                          <Link
                            key={c.event_id ?? c.label}
                            to="/sessions/$sessionId"
                            params={{ sessionId: c.session_id }}
                            onClick={() => c.attacker_ip && selectAttacker(c.attacker_ip)}
                            className="mono-ip border border-border px-1.5 py-1 text-[10px] text-primary hover:border-primary/50"
                          >
                            {c.label}
                          </Link>
                        ) : (
                          <span
                            key={c.event_id ?? c.label}
                            className="mono-ip border border-border px-1.5 py-1 text-[10px] text-muted-foreground"
                          >
                            {c.label}
                          </span>
                        ),
                      )}
                    </div>
                  ) : null}
                </div>
              </div>
            ))}

            {isPending ? (
              <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
                <Loader2 className="h-3 w-3 animate-spin" /> retrieving events…
              </div>
            ) : null}
          </div>

          <form
            onSubmit={(e) => {
              e.preventDefault();
              ask(input);
            }}
            className="flex items-center gap-2 border-t border-border p-2.5"
          >
            <input
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="Ask about attackers, honeypots, techniques…"
              className="h-8 flex-1 border border-input bg-surface-raised px-2 text-xs text-foreground placeholder:text-muted-foreground/60 focus:border-primary focus:outline-none"
            />
            <button
              type="submit"
              disabled={isPending || !input.trim()}
              aria-label="Send"
              className="flex h-8 w-8 shrink-0 items-center justify-center bg-primary text-primary-foreground disabled:opacity-40"
            >
              <Send className="h-3.5 w-3.5" />
            </button>
          </form>
        </div>
      ) : (
        <button
          type="button"
          onClick={() => setOpen(true)}
          aria-label="Open threat assistant"
          data-testid="assistant-toggle"
          className="fixed right-3 bottom-3 z-40 flex h-11 w-11 items-center justify-center border border-primary/40 bg-primary text-primary-foreground shadow-lg hover:opacity-90 sm:right-5 sm:bottom-5"
        >
          <Bot className="h-5 w-5" />
        </button>
      )}
    </>
  );
}
