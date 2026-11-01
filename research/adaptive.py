"""One shared prefix stopping policy for offline evaluation and incremental serving."""
import numpy as np

STAGES = (4, 8, 16, 32)


def accept(probabilities, threshold=.95, entropy_limit=.8):
    p = np.asarray(probabilities, dtype=float)
    entropy = -(p * np.log(np.maximum(p, 1e-12))).sum(axis=-1) / np.log(p.shape[-1])
    return (p.max(axis=-1) >= threshold) & (entropy <= entropy_limit)


def decide(probabilities, lengths, threshold=.95, entropy_limit=.8, fixed=None):
    """Never use a later prefix to choose an earlier decision.

    Short sessions use their true terminal length, not invented padding packets.
    A rejection at the final context is explicitly returned as -1.
    """
    p = np.asarray(probabilities)
    lengths = np.asarray(lengths)
    selected = np.full(len(p), len(STAGES) - 1, dtype=int)
    active = np.ones(len(p), dtype=bool)
    for index, stage in enumerate(STAGES):
        terminal = lengths <= stage
        eligible = np.ones(len(p), dtype=bool) if fixed is None else np.full(len(p), stage >= fixed)
        stop = active & (terminal | (eligible & accept(p[:,index], threshold, entropy_limit)))
        if fixed is not None: stop = active & (terminal | eligible)
        selected[stop] = index; active[stop] = False
    if fixed is not None:selected[:]=STAGES.index(fixed)
    chosen = p[np.arange(len(p)), selected]
    accepted = accept(chosen, threshold, entropy_limit)
    return dict(prediction=np.where(accepted, chosen.argmax(1), -1), raw_prediction=chosen.argmax(1),
                probabilities=chosen, stage_index=selected, packets=np.minimum(lengths, np.asarray(STAGES)[selected]))


class IncrementalDecision:
    """Requests 4→8→16→32 observations without reusing future context."""
    def __init__(self, infer, threshold=.95, entropy_limit=.8, fixed=None):
        self.infer = infer; self.threshold = threshold; self.entropy_limit = entropy_limit; self.fixed = fixed
        self.count = 0; self.result = None; self.calls = 0

    def observe(self, context, terminal=False):
        if self.result is not None: return self.result
        self.count = len(context)
        target = self.fixed or next((stage for stage in STAGES if stage >= self.count), STAGES[-1])
        if not terminal and (self.count < target or self.count not in STAGES): return None
        self.calls += 1
        p = np.asarray(self.infer(context), dtype=float)
        accepted = bool(accept(p, self.threshold, self.entropy_limit))
        if accepted or terminal or self.count >= (self.fixed or STAGES[-1]):
            self.result = dict(prediction=int(p.argmax()) if accepted else -1, probabilities=p.tolist(),
                               packets=self.count, calls=self.calls, terminal=terminal)
        return self.result
