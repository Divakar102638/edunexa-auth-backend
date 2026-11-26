import { Datastore } from '@zcatalyst/datastore';

export async function insertAuditEvent(catalystApp, event) {
  const table = new Datastore(catalystApp).table('audit_events');
  return table.insertRow(event);
}
