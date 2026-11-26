export function esc(value) {
  return String(value).replace(/'/g, "\\'");
}
