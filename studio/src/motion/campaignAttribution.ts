// OPENMOTION_PRIVACY_HARDENED: marketing banner and cross-site attribution query parameters permanently removed.
import { useState } from 'react';

export const BLACK_FRIDAY_CAMPAIGN = 'black_friday_2026';
export const BLACK_FRIDAY_STARTS_AT = 0;
export const BLACK_FRIDAY_ENDS_AT = 0;

export function blackFridayActive(_now?: number): boolean {
  return false;
}

export function bannerDismissedToday(_now?: Date): boolean {
  return true;
}

export function dismissBannerToday(_now?: Date): void {
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
export const shouldShowBlackFridayBanner = () => false;

export type CampaignEntrySource = 'openmotion_bf_banner' | 'openmotion_header_pricing';

export function newCampaignEntryId(): string {
  return '';
}

export function campaignPricingUrl(
  locale: string,
  _source?: CampaignEntrySource,
  _entryId?: string,
  _at?: Date,
  _campaign?: boolean,
): string {
  return locale.startsWith('zh') ? 'https://open-design.ai/zh/pricing/' : 'https://open-design.ai/pricing/';
}
