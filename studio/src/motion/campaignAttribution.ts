// OPENMOTION_PRIVACY_HARDENED: campaign links and cross-site attribution permanently removed.
import { useCallback, useEffect, useState } from 'react';
import type { ExploreFilters } from './workspacePageRouting';

export const BLACK_FRIDAY_CAMPAIGN = 'black_friday_2026';
export const BLACK_FRIDAY_STARTS_AT = 0;
export const BLACK_FRIDAY_ENDS_AT = 0;
export const BLACK_FRIDAY_HERO_STARTS_AT = 0;
export const BLACK_FRIDAY_HERO_ENDS_AT = 0;
export const COUNTDOWN_CYCLE_SECONDS = 12 * 60 * 60;

export function blackFridayActive(_now = Date.now()): boolean {
  return false;
}

export function blackFridayHeroActive(_now = Date.now()): boolean {
  return false;
}

export function readBlackFridayCountdown(_now = Date.now()) {
  return { hours: '00', minutes: '00', seconds: '00', datetime: 'PT00H00M00S' };
}

export function bannerDismissedToday(_now = new Date()): boolean {
  return true;
}

export function dismissBannerToday(_now = new Date()): void {
  // No-op.
}

export function resetBannerDismissal(): void {
  // No-op.
}

export function useMinuteCondition(read: () => boolean) {
  const [value, setValue] = useState(read);
  return [value, setValue] as const;
}

export const useBlackFridayActive = () => false;

export function useExploreCampaign(_filters: ExploreFilters) {
  const [active, setActive] = useMinuteCondition(() => false);
  const expire = useCallback(() => setActive(false), [setActive]);
  return { showHero: active, expire };
}

export type ExploreCampaign = ReturnType<typeof useExploreCampaign>;

export const shouldShowBlackFridayBanner = () => false;

export type CampaignEntrySource = 'openmotion_bf_banner' | 'openmotion_bf_hero' | 'openmotion_bf_hub' | 'openmotion_header_pricing';

export function newCampaignEntryId(): string {
  return '';
}

export function campaignPricingUrl(
  locale: string,
  _source?: CampaignEntrySource,
  _entryId?: string,
  _at = new Date(),
  _campaign = false,
): string {
  return locale.startsWith('zh') ? 'https://open-design.ai/zh/pricing/' : 'https://open-design.ai/pricing/';
}
