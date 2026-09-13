# DONUTMINE

Dark DonutSMP-inspired arcade UI with Minecraft verification, server-side game state, provably-fair rounds, staff tools and promo codes.

## Start

```powershell
npm install
node server.js
```

Open `http://127.0.0.1:3000`.

## Minecraft

Put the Microsoft account email used by the Mineflayer bot in `.env` as `MC_USERNAME`.
The bot reads Minecraft chat in the backend only and watches for exact payment messages to `ZynqelYT`.

Minecraft usernames may use the Bedrock-style leading dot, for example `.OGCR7siu`.

## Staff

The login modal contains a Staff Login tab. Defaults:

- Email: `admin123@gmail.com`
- Password: `admin123123123@@`

Change them in `.env` before public deployment.

Staff is displayed as **ZynqelYT** with the Minecraft skin avatar and cannot place player bets.

## Promo codes

Staff can:

- generate codes like `XXX-XXX-XXX`
- create custom codes from 1–128 characters using letters/numbers/`_`/`-`
- choose the reward amount
- choose the total number of redemptions
- delete codes
- view current usage

Players have a Promo Code section on the site. A code can only be redeemed once per normalized Minecraft account, and the server enforces the total usage cap.

## VPN / proxy blocker

Set `VPN_BLOCKER=1`. For real IP intelligence, add a `VPN_BLOCKER_API_KEY` from ProxyCheck. Local/private addresses are allowed so local development does not lock itself out. If the external checker is unavailable, the server fails open rather than incorrectly blocking users.

## Provably fair

Every game round creates a fresh random server seed, exposes its SHA-256 commitment before play, derives deterministic HMAC-SHA256 values from server seed + client seed + nonce/cursor, and reveals the server seed after settlement.

The hidden outcome bands used by the current demo engine are 65% loss / 25% win / 10% tie. The band is derived from the committed round seed, so it does not reset through mutable browser state or use `Math.random()` for the final settlement.
