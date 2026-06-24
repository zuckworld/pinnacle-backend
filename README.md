# Backend (Render) deployment

Place backend code in this folder and commit to a new GitHub repo. On Render create a new Web Service and point the root to this repository (root).

Required environment variables (set these on Render's dashboard):
- `MONGODB_URI` — Mongo Atlas connection string
- `JWT_SECRET` — random secret for signing tokens
- `ADMIN_SECRET` — admin setup secret header
- `PORT` — typically left unset (Render provides one) or set to `10000`
- `FRONTEND_ORIGIN` — origin to allow for CORS (your Vercel URL)

Start command: `npm start`
Build: none (Node service)

Notes:
- Do NOT commit a real `.env` file. Use `.env.example` as a template.
- Add the repository to Render and set the environment variables via the dashboard.
