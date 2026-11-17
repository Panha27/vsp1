# Crazy DES — three ways to run it

| Package | How | Database / single-device login |
|---|---|---|
| `vsp-quiz-site.zip` | Upload the folder in the Cloudflare dashboard ("Upload static files"), or run it offline on your PC with START-OFFLINE.bat | No - accounts and progress stay in each browser |
| `vsp-worker-package.zip` | `npx wrangler deploy` (needs Node.js) | Yes - uses your D1 database "vsp" |

## Database route (Worker + D1)
1. Install Node.js LTS (https://nodejs.org).
2. Unzip `vsp-worker-package.zip`, open the folder, type `cmd` in the File Explorer address bar, press Enter.
3. `npx wrangler login`
4. Open `wrangler.toml` and paste the Database ID of your D1 database `vsp`
   (dashboard -> Storage & databases -> D1 -> vsp).
5. `npx wrangler secret put ADMIN_PASSWORD`  (type the admin password; it is never stored in the files)
6. `npx wrangler deploy`
7. Log in as `admin`, then Admin -> Accounts -> Reset password to set a private password.

The tables are created automatically on the first request. Back up from Admin -> Backup & update.
