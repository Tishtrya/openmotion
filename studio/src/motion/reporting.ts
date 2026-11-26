// Shared building blocks for page-level reporting modules (template library, Skills, Brand Kit).
// One implementation of the closed-field rules, so every page sends values the server admits.
import { slug } from '../../../tracking/core.ts';
import type { EventFields } from '../../../tracking/core.ts';
import { studioEvents } from '../../../tracking/events.ts';
import type { StudioEvent } from '../../../tracking/events.ts';

export type Fields<E extends StudioEvent> = EventFields<typeof studioEvents[E]>;

/** Fire and forget: reporting never interrupts browsing, copying or downloading. */
// The transport is loaded on first use, so modules that only import a reporter (and tests without a browser) never start it.
// OPENMOTION_PRIVACY_HARDENED: Studio reporting transport permanently disabled.
export const loadReportingTransport = async () => ({});
export const send = <E extends StudioEvent>(_event: E, _properties: Fields<E>) => {};
export const newTrackingId = () => crypto.randomUUID();
/** The settled search-box value as it is reported: trimmed, control characters removed, at most 100 characters. */
export const searchKeyword = (query: string) => query.replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, 100).trim();
/** A catalogue id is sent only when it is a bounded slug; anything else is left out, never rewritten. */
export const slugField = <K extends string>(key: K, value: string | undefined): Partial<Record<K, string>> =>
  value !== undefined && slug.test(value) ? { [key]: value } as Record<K, string> : {};
/** A catalogue model key `provider:modelId` as two bounded fields. Custom providers (`custom-…`) and ids outside the rules are left out. */
export function modelFields(key: string | null | undefined): { model_provider?: string; model_id?: string } {
  if (!key) return {};
  const split = key.indexOf(':');
  const provider = split > 0 ? key.slice(0, split) : undefined;
  const model = split > 0 ? key.slice(split + 1) : key;
  if (provider?.startsWith('custom-')) return {};
  return { ...slugField('model_provider', provider), ...(/^[A-Za-z0-9_.-]{1,128}$/.test(model) ? { model_id: model } : {}) };
}
/** Whether the application is shown inside a host (same rule as the studio page view). */
export const embeddedView = () => new URLSearchParams(location.search).get('embed') === '1';
/** A catalogue option as a stable id. Display text never leaves the browser; an option that cannot be reduced to a slug is left out. */
export function optionId(value: string) {
  const id = value.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 64).replace(/-$/, '');
  return slug.test(id) ? { filter_value: id } : {};
}
