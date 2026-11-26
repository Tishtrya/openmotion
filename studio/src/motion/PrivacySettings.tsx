// OPENMOTION_PRIVACY_HARDENED: telemetry permanently disabled in this privacy-hardened build.
import { IconButton } from 'open-design-ui/icon-button';
import { useEffect, useRef } from 'react';
import { useI18n } from '../i18n/I18n';
import { DiagnosticExport } from './DiagnosticExport';
import { Toggle } from './settingsPrimitives';

export function PrivacySettings({ onClose, embedded = false }: { onClose: () => void; embedded?: boolean }) {
  const { t } = useI18n(), dialog = useRef<HTMLDialogElement>(null);
  useEffect(() => { if (!embedded) dialog.current?.showModal(); return () => dialog.current?.close(); }, [embedded]);

  const content = <>
    <section className={embedded ? 'om-card om-card-stack' : undefined}>
      <div className="om-settings-row">
        <label className="om-subtitle">{t('Share usage data')}</label>
        <Toggle label={t('Share usage data')} checked={false} disabled onChange={() => {}} />
      </div>
      <p className="om-muted" role="status">
        {t('Telemetry, hardware fingerprinting, and usage reporting have been permanently removed in this privacy-hardened build.')}
      </p>
    </section>
    <section className={embedded ? 'om-card om-card-stack' : undefined}>
      <DiagnosticExport />
    </section>
  </>;

  if (embedded) return content;
  return <dialog ref={dialog} className="motion-model-dialog motion-media-surface motion-privacy-dialog" aria-labelledby="privacy-settings-title" onCancel={event => { event.preventDefault(); onClose(); }}>
    <header><h2 id="privacy-settings-title">{t('Privacy settings')}</h2><IconButton variant="plain" className="motion-media-close" aria-label={t('Close')} onClick={onClose} icon="×" /></header>
    {content}
  </dialog>;
}
