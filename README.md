# MpesaHub

Users sign up, create payment channels (their own till/paybill + their own Daraja credentials),
and send STK pushes. Money goes to the channel owner's till, never to the platform.

## Run
1. Install Node 18+.
2. `npm install`
3. `cp .env.example .env` and fill it in (generate ENC_KEY and SESSION_SECRET as shown there).
4. Start a tunnel for the callback: `ngrok http 3000`, then put the https URL in PUBLIC_URL.
5. `npm start` and open http://localhost:3000

## Sandbox testing
Use Daraja sandbox credentials, shortcode 174379 and the sandbox passkey from the Daraja portal.

## Going live
Each user needs their own Daraja app, approved through Safaricom's Go Live process.
For a till, use the till number plus the store (head office) number, with the passkey Safaricom issues.
Back up data.db and keep .env private; losing ENC_KEY makes stored credentials unreadable.
