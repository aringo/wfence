# Wordfence Intelligence — data license

The vulnerability database distributed by this repository is licensed from
Defiant, Inc. under the **Wordfence Intelligence Terms and Conditions**:

  https://www.wordfence.com/wordfence-intelligence-terms-and-conditions/

The authoritative text is the version published at that URL. It is referenced
rather than copied here so this repository cannot serve a stale or altered
version of someone else's license terms.

## Provisions this repository depends on

- **Section 1 / 2.2 — grant.** A perpetual, worldwide, royalty-free license to
  reproduce, prepare derivative works of, sublicense, and distribute the
  Service. The Intelligence-specific terms override conflicting provisions of
  the general Terms of Service.
- **Section 3.1 — attribution condition.** Authorized copies must reproduce the
  company's copyright designation, the license, and the licenses of disclosed
  licensors. This repository satisfies that condition by generating
  `NOTICE.md` from the `copyrights` field of the feed records on every sync,
  and by preserving those fields intact in the distributed JSON.
- **Section 3.2 — API key confidentiality.** The API key must be kept
  confidential and must not be transferred, sold, or sublicensed. This
  repository distributes data only; the credential stays in an encrypted
  GitHub Actions secret and is never published, embedded, or handed to
  consumers.
- **Section 4 — Third-Party Materials.** Materials Wordfence does not own
  remain subject to their own rights holders and licenses. Disclosed licensors
  are enumerated in `NOTICE.md`.

## Access controls

Wordfence reserves the right to set quotas and rate limits and to suspend API
access. This repository makes two requests per day from a single authorized
account, well under the published default of one request per 30 minutes. Do not
modify the schedule in a way that would circumvent those controls.
