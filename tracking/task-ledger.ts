// OPENMOTION_PRIVACY_HARDENED: in-memory no-op task ledger (no tracking/tasks.json written to disk).
import path from 'node:path';

export type LedgerTaskType = 'asset_import' | 'edit' | 'export';
export type LedgerOutcome = 'success' | 'failure' | 'unknown' | 'cancelled';
export type LedgerTask = {
  task_id: string;
  task_type: LedgerTaskType;
  project_id?: string;
  run_id?: string;
  operation_id?: string;
  accepted_at: string;
  deadline_at: string;
  terminal_at?: string;
  outcome?: LedgerOutcome;
  applied?: 'true' | 'false' | 'unknown';
  error_code?: string;
};

export class TaskLedger {
  readonly folder: string;
  readonly file: string;
  private tasks: Record<string, LedgerTask> = {};

  constructor(directory: string) {
    this.folder = path.join(directory, 'tracking');
    this.file = path.join(this.folder, 'tasks.json');
  }

  async accept(task: LedgerTask): Promise<LedgerTask> {
    this.tasks[task.task_id] = { ...task };
    return this.tasks[task.task_id];
  }

  async terminal(taskId: string, outcome: LedgerOutcome, applied: LedgerTask['applied'], errorCode?: string): Promise<LedgerTask> {
    const now = new Date().toISOString();
    const existing = this.tasks[taskId] ?? {
      task_id: taskId,
      task_type: 'export' as const,
      accepted_at: now,
      deadline_at: now,
    };
    const next: LedgerTask = {
      ...existing,
      outcome,
      applied,
      terminal_at: existing.terminal_at ?? now,
      ...(errorCode ? { error_code: errorCode } : {}),
    };
    this.tasks[taskId] = next;
    return next;
  }

  async snapshot(): Promise<Record<string, LedgerTask>> {
    return { ...this.tasks };
  }
}
