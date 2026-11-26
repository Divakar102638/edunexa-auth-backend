import catalyst from 'zcatalyst-sdk-node';

export function initializeCatalyst(req) {
  return catalyst.initialize(req);
}
