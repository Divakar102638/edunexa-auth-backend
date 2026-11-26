export function esc(value) {
  const text = String(value);
  if (!/^[A-Za-z0-9_-]+$/.test(text)) {
    throw new TypeError('Invalid value for a ZCQL identifier literal');
  }
  return text;
}
