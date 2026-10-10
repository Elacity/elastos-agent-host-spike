// The exact command the owner runs on the Home computer to arm recovery for
// this page. The passkey rp id is the page's host name.
export function ownerRecoveryCommand({ origin, hostname }) {
  return `elastos identity arm-owner-recovery --origin ${origin} --rp-id ${hostname}`;
}
