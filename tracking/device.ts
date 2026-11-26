// OPENMOTION_PRIVACY_HARDENED: hardware/OS device fingerprinting permanently removed.
export type DeviceIdentity = { device_id: string; device_id_source: 'platform' | 'unavailable' };
export const unknownDevice: DeviceIdentity = { device_id: 'unknown', device_id_source: 'unavailable' };

export function deviceIdentity(_platform: string, _identifier: string): DeviceIdentity {
  return unknownDevice;
}

export function loadDeviceIdentity(): Promise<DeviceIdentity> {
  return Promise.resolve(unknownDevice);
}
