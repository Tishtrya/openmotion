import type { GalleryTemplate } from '../../../shared/catalog';
export const GITHUB_REPOSITORY = 'https://github.com/nexu-io/openmotion';
export const repositorySupportLinks = [
  { label: "What's new", href: `${GITHUB_REPOSITORY}/releases`, icon: 'history-line' },
  { label: 'Feedback', href: `${GITHUB_REPOSITORY}/issues/new/choose`, icon: 'chat-1-line' },
] as const;
// OPENMOTION_PRIVACY_HARDENED: background GitHub Stars API fetch removed.

export function templateRepositoryUrl(template: GalleryTemplate): string {
  if (['product-promo', 'nyt-graph', 'decision-tree'].includes(template.id)) return `${GITHUB_REPOSITORY}/tree/main/template-library/${template.id}`;
  if (/^motion-[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/.test(template.id)) return `${GITHUB_REPOSITORY}/tree/main/library/templates/catalog/${template.id}`;
  return `${GITHUB_REPOSITORY}/tree/main/library/templates`;
}

// OPENMOTION_PRIVACY_HARDENED: background GitHub Stars API reader disabled.
export function createRepositoryStarsReader() {
  return function readStars(): Promise<number | null> {
    return Promise.resolve(null);
  };
}

export const readRepositoryStars = createRepositoryStarsReader();
