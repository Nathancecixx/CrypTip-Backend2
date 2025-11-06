export function log(event: string, fields: Record<string, unknown> = {}) {
  const rec = { ts: new Date().toISOString(), event, ...fields };
  console.log(JSON.stringify(rec));
}
