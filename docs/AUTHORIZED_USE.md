# Authorized use

NetScan is a network discovery and load-testing tool. It is powerful enough to
find hosts, enumerate services and generate sustained traffic. Using it against
systems you do not control is illegal in many jurisdictions and can disrupt
production services. This document describes the standard we expect from every
user and contributor.

## The short version

**Only scan or load-test systems you own or have explicit, written permission
to test.**

If you are unsure whether you have permission, you do not have it. Ask the
system owner in writing before you run anything.

## What counts as authorization

Acceptable authorization is specific and verifiable. It usually includes:

- the systems or address ranges in scope;
- the type of testing allowed (discovery, port scanning, load testing);
- the time window and any rate limits;
- a named contact who can approve or stop the work;
- a ticket, change record, contract or signed engagement letter.

A verbal "sure, go ahead" from someone who does not own the system is not
enough. Neither is a public IP address, a shared hosting account, or a service
you pay for but do not operate.

## Rules of engagement

1. **Stay in scope.** Use `--scope-file` to encode the allowlist and
   `--exclude` for anything that must not be touched. NetScan enforces both
   before sending traffic.
2. **Start gently.** Use `--intensity polite` for discovery and start load
   tests below the expected capacity. Ramp up with `--ramp` instead of opening
   at full rate.
3. **Respect the caps.** The hard limits exist for a reason. Do not patch them
   out for a "quick" run.
4. **Watch the target.** Stop immediately if the service degrades, if the
   operator asks you to stop, or if you see errors you did not expect.
5. **Protect data.** Reports can contain hostnames, MAC addresses, banners and
   certificate metadata. Store and share them accordingly.
6. **Keep records.** Use `--operator`, `--authorization-ref` and `--note`, and
   keep the JSON or HTML report with the authorization.
7. **Do not target third parties.** No spoofing, reflection, amplification or
   "testing" a provider's shared infrastructure without their explicit consent.

## What NetScan deliberately cannot do

The load tester is single-origin by design. It:

- requires an explicit `--authorize` acknowledgement;
- refuses public targets unless `--allow-public` is also given;
- refuses multicast, broadcast, reserved and unspecified addresses;
- caps duration, concurrency, request rate and payload size;
- follows redirects only within the same origin;
- has no raw sockets, address spoofing, reflection or amplification.

These are not obstacles to work around. They are the boundary of the tool's
intended use.

## Reporting misuse

If you believe NetScan is being used against systems without authorization,
contact the maintainers privately. Do not attempt to investigate the target
yourself.

## Legal

This document is guidance, not legal advice. Laws differ by country and by
contract. You are responsible for confirming that your activity is lawful and
authorized before you run NetScan.
