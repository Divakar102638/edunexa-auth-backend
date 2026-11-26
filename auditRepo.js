export async function insertAuditEvent(catalystApp, event) {
  const table = catalystApp.datastore().table('audit_events');
  return table.insertRow(event);
}
